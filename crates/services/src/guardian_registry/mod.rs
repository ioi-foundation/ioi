use async_trait::async_trait;
use ioi_api::services::{BlockchainService, UpgradableService};
use ioi_api::state::StateAccess;
use ioi_api::transaction::context::TxContext;
use ioi_crypto::algorithms::hash::sha256;
use ioi_types::app::{
    aft_archived_recovered_history_checkpoint_hash_key,
    aft_archived_recovered_history_checkpoint_key,
    aft_archived_recovered_history_profile_activation_hash_key,
    aft_archived_recovered_history_profile_activation_height_key,
    aft_archived_recovered_history_profile_activation_key,
    aft_archived_recovered_history_profile_hash_key,
    aft_archived_recovered_history_retention_receipt_key,
    aft_archived_recovered_history_segment_hash_key, aft_archived_recovered_history_segment_key,
    aft_archived_recovered_history_segment_prefix, aft_archived_recovered_restart_page_key,
    aft_bulletin_availability_certificate_key, aft_bulletin_commitment_key, aft_bulletin_entry_key,
    aft_canonical_bulletin_close_key, aft_canonical_collapse_object_key,
    aft_canonical_order_abort_key, aft_missing_recovery_share_key, aft_omission_proof_key,
    aft_order_certificate_key, aft_publication_frontier_contradiction_key,
    aft_publication_frontier_key, aft_recovered_publication_bundle_key,
    aft_recovered_publication_bundle_prefix, aft_recovery_capsule_key,
    aft_recovery_share_material_key, aft_recovery_share_material_prefix,
    aft_recovery_share_receipt_key, aft_recovery_share_receipt_prefix,
    aft_recovery_witness_certificate_key, bind_canonical_collapse_continuity,
    build_archived_recovered_history_checkpoint, build_archived_recovered_history_profile,
    build_archived_recovered_history_profile_activation,
    build_archived_recovered_history_retention_receipt, build_archived_recovered_restart_page,
    canonical_archived_recovered_history_checkpoint_hash,
    canonical_archived_recovered_history_profile_activation_hash,
    canonical_archived_recovered_history_profile_hash,
    canonical_archived_recovered_history_retention_receipt_hash,
    canonical_archived_recovered_history_segment_hash,
    canonical_archived_recovered_restart_page_hash, canonical_asymptote_observer_assignment_hash,
    canonical_asymptote_observer_canonical_abort_hash,
    canonical_asymptote_observer_canonical_close_hash,
    canonical_asymptote_observer_challenges_hash,
    canonical_asymptote_observer_observation_request_hash,
    canonical_asymptote_observer_transcript_hash, canonical_bulletin_availability_certificate_hash,
    canonical_bulletin_close_hash, canonical_bulletin_commitment_hash,
    canonical_collapse_archived_recovered_history_anchor,
    canonical_collapse_eq_ignoring_archived_recovered_history_anchor,
    canonical_collapse_historical_continuation_anchor, canonical_order_abort_hash,
    canonical_order_certificate_hash, canonical_order_publication_bundle_hash,
    canonical_publication_frontier_hash, canonical_recoverable_slot_payload_v4_hash,
    canonical_recoverable_slot_payload_v5_hash, canonical_recovery_capsule_hash,
    canonical_replay_prefix_entry, canonical_replay_prefix_historical_continuation_anchor,
    canonical_validator_sets_hash, derive_canonical_collapse_object_from_recovered_surface,
    effective_set_for_height, evidence_id, extract_canonical_bulletin_surface,
    guardian_registry_asymptote_policy_key, guardian_registry_committee_account_key,
    guardian_registry_committee_key, guardian_registry_effect_nullifier_key,
    guardian_registry_effect_verifier_key, guardian_registry_log_key,
    guardian_registry_observer_canonical_abort_key, guardian_registry_observer_canonical_close_key,
    guardian_registry_observer_challenge_commitment_key, guardian_registry_observer_challenge_key,
    guardian_registry_observer_transcript_commitment_key,
    guardian_registry_observer_transcript_key, guardian_registry_sealed_effect_key,
    guardian_registry_witness_fault_key, guardian_registry_witness_key,
    guardian_registry_witness_seed_key, guardian_registry_witness_set_key,
    normalize_recovered_publication_bundle_supporting_witnesses, read_validator_sets,
    recover_canonical_order_artifact_surface_from_share_materials,
    recover_full_canonical_order_surface_from_share_materials, recovered_canonical_header_entry,
    recovered_certified_header_entry, recovered_certified_header_prefix,
    recovered_restart_block_header_entry, set_canonical_collapse_archived_recovered_history_anchor,
    stitch_recovered_canonical_header_segments, stitch_recovered_canonical_header_windows,
    stitch_recovered_certified_header_segments, stitch_recovered_certified_header_windows,
    stitch_recovered_restart_block_header_segments, stitch_recovered_restart_block_header_windows,
    validate_archived_recovered_history_checkpoint_against_profile,
    validate_archived_recovered_history_profile,
    validate_archived_recovered_history_profile_activation,
    validate_archived_recovered_history_profile_activation_against_checkpoint,
    validate_archived_recovered_history_profile_activation_checkpoint,
    validate_archived_recovered_history_profile_activation_covering_tip_height,
    validate_archived_recovered_history_profile_activation_successor,
    validate_archived_recovered_history_retention_receipt_against_profile,
    validate_archived_recovered_history_segment_against_profile,
    validate_archived_recovered_history_segment_predecessor,
    validate_archived_recovered_restart_page_against_profile, validate_recovered_page_coverage,
    verify_canonical_collapse_continuity, verify_canonical_order_publication_bundle,
    verify_publication_frontier_contradiction, write_validator_sets, AccountId,
    AftHistoricalContinuationSurface, AftRecoveredStateSurface, ArchivedRecoveredHistoryCheckpoint,
    ArchivedRecoveredHistoryProfile, ArchivedRecoveredHistoryProfileActivation,
    ArchivedRecoveredHistoryRetentionReceipt, ArchivedRecoveredHistorySegment,
    ArchivedRecoveredRestartPage, AsymptoteObserverCanonicalAbort, AsymptoteObserverCanonicalClose,
    AsymptoteObserverChallenge, AsymptoteObserverChallengeCommitment,
    AsymptoteObserverChallengeKind, AsymptoteObserverSealingMode, AsymptoteObserverTranscript,
    AsymptoteObserverTranscriptCommitment, AsymptotePolicy, BulletinAvailabilityCertificate,
    BulletinCommitment, BulletinSurfaceEntry, CanonicalBulletinClose, CanonicalCollapseKind,
    CanonicalCollapseObject, CanonicalOrderAbort, CanonicalOrderAbortReason,
    CanonicalOrderCertificate, CanonicalOrderPublicationBundle, CanonicalReplayPrefixEntry,
    CollapseState, EffectProofVerifierDescriptor, FailureReport, FinalityTier,
    GuardianCommitteeManifest, GuardianLogCheckpoint, GuardianMeasurementProfile,
    GuardianTransparencyLogDescriptor, GuardianWitnessCommitteeManifest, GuardianWitnessEpochSeed,
    GuardianWitnessFaultEvidence, GuardianWitnessSet, MissingRecoveryShare, OffenseFacts,
    OffenseType, OmissionProof, ProofOfDivergence, PublicationFrontier,
    PublicationFrontierContradiction, PublicationFrontierContradictionKind,
    RecoveredCanonicalHeaderEntry, RecoveredCertifiedHeaderEntry, RecoveredPublicationBundle,
    RecoveredRestartBlockHeaderEntry, RecoveredSegmentFoldPage, RecoveryCapsule,
    RecoveryShareMaterial, RecoveryShareReceipt, RecoveryWitnessCertificate, SealedEffectRecord,
    AFT_ACTIVE_ARCHIVED_RECOVERED_HISTORY_PROFILE_KEY,
    AFT_ARCHIVED_RECOVERED_HISTORY_PROFILE_ACTIVATION_HEIGHT_PREFIX, AFT_BULLETIN_ENTRY_PREFIX,
    AFT_LATEST_ARCHIVED_RECOVERED_HISTORY_CHECKPOINT_KEY,
    AFT_LATEST_ARCHIVED_RECOVERED_HISTORY_PROFILE_ACTIVATION_KEY,
    AFT_RECOVERED_PUBLICATION_BUNDLE_PREFIX, AFT_RECOVERY_WITNESS_CERTIFICATE_PREFIX,
    GUARDIAN_REGISTRY_CHECKPOINT_PREFIX, GUARDIAN_REGISTRY_EQUIVOCATION_PREFIX,
    GUARDIAN_REGISTRY_MEASUREMENT_PREFIX, GUARDIAN_REGISTRY_OBSERVER_CHALLENGE_PREFIX,
};
use ioi_types::codec;
use ioi_types::config::GuardianRegistryParams;
use ioi_types::error::{StateError, TransactionError, UpgradeError};
use ioi_types::keys::{EVIDENCE_REGISTRY_KEY, QUARANTINED_VALIDATORS_KEY, VALIDATOR_SET_KEY};
use ioi_types::service_configs::Capabilities;
use std::any::Any;
use std::collections::{BTreeMap, BTreeSet};
use tracing::warn;

#[derive(Debug, Clone)]
pub struct GuardianRegistry {
    pub config: GuardianRegistryParams,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryThresholdStatus {
    Pending,
    Recoverable([u8; 32]),
    Impossible,
}

impl GuardianRegistry {
    pub fn new(config: GuardianRegistryParams) -> Self {
        Self { config }
    }

    pub fn manifest_hash(
        manifest: &GuardianCommitteeManifest,
    ) -> Result<[u8; 32], TransactionError> {
        let bytes = codec::to_bytes_canonical(manifest).map_err(TransactionError::Serialization)?;
        sha256(&bytes)
            .map_err(|e| TransactionError::Invalid(e.to_string()))
            .and_then(|digest| {
                digest
                    .try_into()
                    .map_err(|_| TransactionError::Invalid("invalid manifest hash length".into()))
            })
    }

    pub fn load_manifest_by_hash(
        state: &dyn StateAccess,
        manifest_hash: &[u8; 32],
    ) -> Result<Option<GuardianCommitteeManifest>, StateError> {
        let key = guardian_registry_committee_key(manifest_hash);
        match state.get(&key)? {
            Some(bytes) => codec::from_bytes_canonical(&bytes)
                .map(Some)
                .map_err(|e| StateError::InvalidValue(e.to_string())),
            None => Ok(None),
        }
    }

    pub fn load_manifest_hash_by_account(
        state: &dyn StateAccess,
        account_id: &AccountId,
    ) -> Result<Option<[u8; 32]>, StateError> {
        let key = guardian_registry_committee_account_key(account_id);
        match state.get(&key)? {
            Some(bytes) => bytes
                .as_slice()
                .try_into()
                .map(Some)
                .map_err(|_| StateError::InvalidValue("invalid guardian manifest hash".into())),
            None => Ok(None),
        }
    }

    pub fn load_witness_manifest_by_hash(
        state: &dyn StateAccess,
        manifest_hash: &[u8; 32],
    ) -> Result<Option<GuardianWitnessCommitteeManifest>, StateError> {
        let key = guardian_registry_witness_key(manifest_hash);
        match state.get(&key)? {
            Some(bytes) => codec::from_bytes_canonical(&bytes)
                .map(Some)
                .map_err(|e| StateError::InvalidValue(e.to_string())),
            None => Ok(None),
        }
    }

    pub fn profile_allows_measurement(
        state: &dyn StateAccess,
        measurement_root: &[u8; 32],
    ) -> Result<bool, StateError> {
        let Some(profile_bytes) =
            state.get(&[GUARDIAN_REGISTRY_MEASUREMENT_PREFIX, b"default"].concat())?
        else {
            return Ok(false);
        };
        let profile: GuardianMeasurementProfile = codec::from_bytes_canonical(&profile_bytes)
            .map_err(|e| StateError::InvalidValue(e.to_string()))?;
        Ok(profile
            .allowed_measurement_roots
            .iter()
            .any(|root| root == measurement_root))
    }

    pub fn load_asymptote_policy(
        state: &dyn StateAccess,
        epoch: u64,
    ) -> Result<Option<AsymptotePolicy>, StateError> {
        match state.get(&guardian_registry_asymptote_policy_key(epoch))? {
            Some(bytes) => codec::from_bytes_canonical(&bytes)
                .map(Some)
                .map_err(|e| StateError::InvalidValue(e.to_string())),
            None => Ok(None),
        }
    }

    pub fn load_bulletin_commitment(
        state: &dyn StateAccess,
        height: u64,
    ) -> Result<Option<BulletinCommitment>, StateError> {
        match state.get(&aft_bulletin_commitment_key(height))? {
            Some(bytes) => codec::from_bytes_canonical(&bytes)
                .map(Some)
                .map_err(|e| StateError::InvalidValue(e.to_string())),
            None => Ok(None),
        }
    }

    pub fn load_bulletin_surface_entries(
        state: &dyn StateAccess,
        height: u64,
    ) -> Result<Vec<BulletinSurfaceEntry>, StateError> {
        let prefix = [AFT_BULLETIN_ENTRY_PREFIX, &height.to_be_bytes()].concat();
        let mut entries = Vec::new();
        for item in state.prefix_scan(&prefix)? {
            let (_, value) = item?;
            let entry: BulletinSurfaceEntry = codec::from_bytes_canonical(&value)
                .map_err(|e| StateError::InvalidValue(e.to_string()))?;
            entries.push(entry);
        }
        entries.sort_unstable_by(|left, right| left.tx_hash.cmp(&right.tx_hash));
        Ok(entries)
    }

    pub fn load_bulletin_availability_certificate(
        state: &dyn StateAccess,
        height: u64,
    ) -> Result<Option<BulletinAvailabilityCertificate>, StateError> {
        match state.get(&aft_bulletin_availability_certificate_key(height))? {
            Some(bytes) => codec::from_bytes_canonical(&bytes)
                .map(Some)
                .map_err(|e| StateError::InvalidValue(e.to_string())),
            None => Ok(None),
        }
    }

    pub fn load_canonical_bulletin_close(
        state: &dyn StateAccess,
        height: u64,
    ) -> Result<Option<CanonicalBulletinClose>, StateError> {
        match state.get(&aft_canonical_bulletin_close_key(height))? {
            Some(bytes) => codec::from_bytes_canonical(&bytes)
                .map(Some)
                .map_err(|e| StateError::InvalidValue(e.to_string())),
            None => Ok(None),
        }
    }

    pub fn extract_published_bulletin_surface(
        state: &dyn StateAccess,
        height: u64,
    ) -> Result<Option<Vec<BulletinSurfaceEntry>>, StateError> {
        let Some(bulletin_commitment) = Self::load_bulletin_commitment(state, height)? else {
            return Ok(None);
        };
        let Some(bulletin_availability_certificate) =
            Self::load_bulletin_availability_certificate(state, height)?
        else {
            return Ok(None);
        };
        let Some(bulletin_close) = Self::load_canonical_bulletin_close(state, height)? else {
            return Ok(None);
        };
        let entries = Self::load_bulletin_surface_entries(state, height)?;
        extract_canonical_bulletin_surface(
            &bulletin_close,
            &bulletin_commitment,
            &bulletin_availability_certificate,
            &entries,
        )
        .map(Some)
        .map_err(StateError::InvalidValue)
    }

    pub fn require_published_bulletin_surface(
        state: &dyn StateAccess,
        height: u64,
    ) -> Result<Vec<BulletinSurfaceEntry>, StateError> {
        let bulletin_commitment =
            Self::load_bulletin_commitment(state, height)?.ok_or_else(|| {
                StateError::InvalidValue(
                    "published bulletin commitment is required for closed-slot extraction".into(),
                )
            })?;
        let bulletin_availability_certificate =
            Self::load_bulletin_availability_certificate(state, height)?.ok_or_else(|| {
                StateError::InvalidValue(
                    "published bulletin availability certificate is required for closed-slot extraction"
                        .into(),
                )
            })?;
        let bulletin_close =
            Self::load_canonical_bulletin_close(state, height)?.ok_or_else(|| {
                StateError::InvalidValue(
                    "canonical bulletin close is required for closed-slot extraction".into(),
                )
            })?;
        let entries = Self::load_bulletin_surface_entries(state, height)?;
        extract_canonical_bulletin_surface(
            &bulletin_close,
            &bulletin_commitment,
            &bulletin_availability_certificate,
            &entries,
        )
        .map_err(StateError::InvalidValue)
    }

    pub fn load_canonical_order_certificate(
        state: &dyn StateAccess,
        height: u64,
    ) -> Result<Option<CanonicalOrderCertificate>, StateError> {
        match state.get(&aft_order_certificate_key(height))? {
            Some(bytes) => codec::from_bytes_canonical(&bytes)
                .map(Some)
                .map_err(|e| StateError::InvalidValue(e.to_string())),
            None => Ok(None),
        }
    }

    pub fn load_canonical_order_abort(
        state: &dyn StateAccess,
        height: u64,
    ) -> Result<Option<CanonicalOrderAbort>, StateError> {
        match state.get(&aft_canonical_order_abort_key(height))? {
            Some(bytes) => codec::from_bytes_canonical(&bytes)
                .map(Some)
                .map_err(|e| StateError::InvalidValue(e.to_string())),
            None => Ok(None),
        }
    }

    pub fn load_publication_frontier(
        state: &dyn StateAccess,
        height: u64,
    ) -> Result<Option<PublicationFrontier>, StateError> {
        match state.get(&aft_publication_frontier_key(height))? {
            Some(bytes) => codec::from_bytes_canonical(&bytes)
                .map(Some)
                .map_err(|e| StateError::InvalidValue(e.to_string())),
            None => Ok(None),
        }
    }

    pub fn load_publication_frontier_contradiction(
        state: &dyn StateAccess,
        height: u64,
    ) -> Result<Option<PublicationFrontierContradiction>, StateError> {
        match state.get(&aft_publication_frontier_contradiction_key(height))? {
            Some(bytes) => codec::from_bytes_canonical(&bytes)
                .map(Some)
                .map_err(|e| StateError::InvalidValue(e.to_string())),
            None => Ok(None),
        }
    }

    pub fn load_recovery_capsule(
        state: &dyn StateAccess,
        height: u64,
    ) -> Result<Option<RecoveryCapsule>, StateError> {
        match state.get(&aft_recovery_capsule_key(height))? {
            Some(bytes) => codec::from_bytes_canonical(&bytes)
                .map(Some)
                .map_err(|e| StateError::InvalidValue(e.to_string())),
            None => Ok(None),
        }
    }

    pub fn load_recovery_witness_certificate(
        state: &dyn StateAccess,
        height: u64,
        witness_manifest_hash: &[u8; 32],
    ) -> Result<Option<RecoveryWitnessCertificate>, StateError> {
        match state.get(&aft_recovery_witness_certificate_key(
            height,
            witness_manifest_hash,
        ))? {
            Some(bytes) => codec::from_bytes_canonical(&bytes)
                .map(Some)
                .map_err(|e| StateError::InvalidValue(e.to_string())),
            None => Ok(None),
        }
    }

    pub fn load_recovery_witness_certificates(
        state: &dyn StateAccess,
        height: u64,
    ) -> Result<Vec<RecoveryWitnessCertificate>, StateError> {
        let prefix = [
            AFT_RECOVERY_WITNESS_CERTIFICATE_PREFIX,
            &height.to_be_bytes(),
        ]
        .concat();
        let mut certificates = Vec::new();
        for item in state.prefix_scan(&prefix)? {
            let (_, value) = item?;
            let certificate: RecoveryWitnessCertificate = codec::from_bytes_canonical(&value)
                .map_err(|e| StateError::InvalidValue(e.to_string()))?;
            certificates.push(certificate);
        }
        certificates.sort_unstable_by(|left, right| {
            left.witness_manifest_hash.cmp(&right.witness_manifest_hash)
        });
        Ok(certificates)
    }

    pub fn load_recovery_share_receipts(
        state: &dyn StateAccess,
        height: u64,
        witness_manifest_hash: &[u8; 32],
    ) -> Result<Vec<RecoveryShareReceipt>, StateError> {
        let prefix = aft_recovery_share_receipt_prefix(height, witness_manifest_hash);
        let mut receipts = Vec::new();
        for item in state.prefix_scan(&prefix)? {
            let (_, value) = item?;
            let receipt: RecoveryShareReceipt = codec::from_bytes_canonical(&value)
                .map_err(|e| StateError::InvalidValue(e.to_string()))?;
            receipts.push(receipt);
        }
        receipts.sort_unstable_by(|left, right| {
            left.block_commitment_hash.cmp(&right.block_commitment_hash)
        });
        Ok(receipts)
    }

    pub fn load_recovery_share_materials(
        state: &dyn StateAccess,
        height: u64,
        witness_manifest_hash: &[u8; 32],
    ) -> Result<Vec<RecoveryShareMaterial>, StateError> {
        let prefix = aft_recovery_share_material_prefix(height, witness_manifest_hash);
        let mut materials = Vec::new();
        for item in state.prefix_scan(&prefix)? {
            let (_, value) = item?;
            let material: RecoveryShareMaterial = codec::from_bytes_canonical(&value)
                .map_err(|e| StateError::InvalidValue(e.to_string()))?;
            materials.push(material);
        }
        materials.sort_unstable_by(|left, right| {
            left.block_commitment_hash.cmp(&right.block_commitment_hash)
        });
        Ok(materials)
    }

    pub fn load_recovery_share_material(
        state: &dyn StateAccess,
        height: u64,
        witness_manifest_hash: &[u8; 32],
        block_commitment_hash: &[u8; 32],
    ) -> Result<Option<RecoveryShareMaterial>, StateError> {
        match state.get(&aft_recovery_share_material_key(
            height,
            witness_manifest_hash,
            block_commitment_hash,
        ))? {
            Some(bytes) => codec::from_bytes_canonical(&bytes)
                .map(Some)
                .map_err(|e| StateError::InvalidValue(e.to_string())),
            None => Ok(None),
        }
    }

    pub fn load_recovered_publication_bundles(
        state: &dyn StateAccess,
        height: u64,
        block_commitment_hash: &[u8; 32],
    ) -> Result<Vec<RecoveredPublicationBundle>, StateError> {
        let prefix = aft_recovered_publication_bundle_prefix(height, block_commitment_hash);
        let mut recovered = Vec::new();
        for item in state.prefix_scan(&prefix)? {
            let (_, value) = item?;
            let object: RecoveredPublicationBundle = codec::from_bytes_canonical(&value)
                .map_err(|e| StateError::InvalidValue(e.to_string()))?;
            recovered.push(object);
        }
        recovered.sort_unstable_by(|left, right| {
            left.supporting_witness_manifest_hashes
                .cmp(&right.supporting_witness_manifest_hashes)
        });
        Ok(recovered)
    }

    fn load_recovered_publication_bundles_for_height(
        state: &dyn StateAccess,
        height: u64,
    ) -> Result<Vec<RecoveredPublicationBundle>, StateError> {
        let prefix = [
            AFT_RECOVERED_PUBLICATION_BUNDLE_PREFIX,
            &height.to_be_bytes(),
        ]
        .concat();
        let mut recovered = Vec::new();
        for item in state.prefix_scan(&prefix)? {
            let (_, value) = item?;
            let object: RecoveredPublicationBundle = codec::from_bytes_canonical(&value)
                .map_err(|e| StateError::InvalidValue(e.to_string()))?;
            recovered.push(object);
        }
        recovered.sort_unstable_by(|left, right| {
            left.block_commitment_hash
                .cmp(&right.block_commitment_hash)
                .then_with(|| {
                    left.supporting_witness_manifest_hashes
                        .cmp(&right.supporting_witness_manifest_hashes)
                })
        });
        Ok(recovered)
    }

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

    fn validate_canonical_collapse_archived_history_anchor(
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

    fn load_latest_canonical_archived_history_anchor_hashes(
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

    pub fn load_aft_historical_continuation_surface_for_height(
        state: &dyn StateAccess,
        height: u64,
    ) -> Result<Option<AftHistoricalContinuationSurface>, StateError> {
        let Some(collapse) = Self::load_canonical_collapse_object(state, height)? else {
            return Ok(None);
        };
        Self::load_aft_historical_continuation_surface_for_collapse(state, &collapse)
    }

    fn load_aft_historical_continuation_surface_for_collapse(
        state: &dyn StateAccess,
        collapse: &CanonicalCollapseObject,
    ) -> Result<Option<AftHistoricalContinuationSurface>, StateError> {
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
                "ordinary historical continuation checkpoint is missing from state".into(),
            )
        })?;
        let activation = Self::load_archived_recovered_history_profile_activation_by_hash(
            state,
            &anchor.profile_activation_hash,
        )?
        .ok_or_else(|| {
            StateError::InvalidValue(
                "ordinary historical continuation profile activation is missing from state".into(),
            )
        })?;
        let receipt = Self::load_archived_recovered_history_retention_receipt(
            state,
            &anchor.checkpoint_hash,
        )?
        .ok_or_else(|| {
            StateError::InvalidValue(
                "ordinary historical continuation retention receipt is missing from state".into(),
            )
        })?;

        if checkpoint.archived_profile_activation_hash != anchor.profile_activation_hash {
            return Err(StateError::InvalidValue(
                "ordinary historical continuation checkpoint activation hash does not match the canonical anchor"
                    .into(),
            ));
        }
        if receipt.archived_profile_activation_hash != anchor.profile_activation_hash {
            return Err(StateError::InvalidValue(
                "ordinary historical continuation retention receipt activation hash does not match the canonical anchor"
                    .into(),
            ));
        }

        Ok(Some(AftHistoricalContinuationSurface {
            anchor,
            checkpoint,
            profile_activation: activation,
            retention_receipt: receipt,
        }))
    }

    fn load_latest_publication_frontier_before(
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

    fn load_unique_recovered_publication_ancestry(
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

    fn load_unique_recovered_publication_bundle_for_height(
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

    fn load_supporting_recovery_share_materials_for_recovered_bundle(
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

    fn reconstruct_recovered_publication_surface(
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

    fn recover_unique_recovered_canonical_header_entry(
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
        let historical_continuation = match replay_prefix.last() {
            Some(entry)
                if canonical_replay_prefix_historical_continuation_anchor(entry)
                    .map_err(StateError::InvalidValue)?
                    .is_some() =>
            {
                Self::load_aft_historical_continuation_surface_for_height(state, end_height)?
            }
            _ => None,
        };

        Ok(AftRecoveredStateSurface {
            replay_prefix,
            consensus_headers,
            certified_headers,
            restart_headers,
            historical_continuation,
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

    pub fn load_observer_challenges(
        state: &dyn StateAccess,
        epoch: u64,
        height: u64,
        view: u64,
    ) -> Result<Vec<AsymptoteObserverChallenge>, StateError> {
        let prefix = [
            GUARDIAN_REGISTRY_OBSERVER_CHALLENGE_PREFIX,
            &epoch.to_be_bytes(),
            &height.to_be_bytes(),
            &view.to_be_bytes(),
        ]
        .concat();
        let mut challenges = Vec::new();
        for item in state.prefix_scan(&prefix)? {
            let (_, value) = item?;
            let challenge: AsymptoteObserverChallenge = codec::from_bytes_canonical(&value)
                .map_err(|e| StateError::InvalidValue(e.to_string()))?;
            challenges.push(challenge);
        }
        challenges.sort_unstable_by_key(|challenge| challenge.challenge_id);
        Ok(challenges)
    }

    pub fn load_effect_proof_verifier(
        state: &dyn StateAccess,
        verifier_id: &str,
    ) -> Result<Option<EffectProofVerifierDescriptor>, StateError> {
        match state.get(&guardian_registry_effect_verifier_key(verifier_id))? {
            Some(bytes) => codec::from_bytes_canonical(&bytes)
                .map(Some)
                .map_err(|e| StateError::InvalidValue(e.to_string())),
            None => Ok(None),
        }
    }

    fn load_quarantined_validators(
        state: &dyn StateAccess,
    ) -> Result<BTreeSet<AccountId>, TransactionError> {
        let set = state
            .get(QUARANTINED_VALIDATORS_KEY)?
            .map(|bytes| codec::from_bytes_canonical(&bytes).map_err(StateError::InvalidValue))
            .transpose()
            .map_err(TransactionError::State)?;
        Ok(set.unwrap_or_default())
    }

    fn load_evidence_registry(
        state: &dyn StateAccess,
    ) -> Result<BTreeSet<[u8; 32]>, TransactionError> {
        let set = state
            .get(EVIDENCE_REGISTRY_KEY)?
            .map(|bytes| codec::from_bytes_canonical(&bytes).map_err(StateError::InvalidValue))
            .transpose()
            .map_err(TransactionError::State)?;
        Ok(set.unwrap_or_default())
    }

    fn build_canonical_order_abort(
        height: u64,
        reason: CanonicalOrderAbortReason,
        details: impl Into<String>,
        certificate: Option<&CanonicalOrderCertificate>,
        close: Option<&CanonicalBulletinClose>,
    ) -> CanonicalOrderAbort {
        let bulletin_commitment_hash = certificate
            .and_then(|candidate| {
                canonical_bulletin_commitment_hash(&candidate.bulletin_commitment).ok()
            })
            .unwrap_or([0u8; 32]);
        let bulletin_availability_certificate_hash = certificate
            .and_then(|candidate| {
                canonical_bulletin_availability_certificate_hash(
                    &candidate.bulletin_availability_certificate,
                )
                .ok()
            })
            .unwrap_or([0u8; 32]);
        let bulletin_close_hash = close
            .and_then(|candidate| canonical_bulletin_close_hash(candidate).ok())
            .unwrap_or([0u8; 32]);
        let canonical_order_certificate_hash = certificate
            .and_then(|candidate| canonical_order_certificate_hash(candidate).ok())
            .unwrap_or([0u8; 32]);
        CanonicalOrderAbort {
            height,
            reason,
            details: details.into(),
            bulletin_commitment_hash,
            bulletin_availability_certificate_hash,
            bulletin_close_hash,
            canonical_order_certificate_hash,
        }
    }

    fn materialize_canonical_order_abort(
        state: &mut dyn StateAccess,
        abort: CanonicalOrderAbort,
    ) -> Result<(), TransactionError> {
        state.insert(
            &aft_canonical_order_abort_key(abort.height),
            &codec::to_bytes_canonical(&abort).map_err(TransactionError::Serialization)?,
        )?;
        state.delete(&aft_order_certificate_key(abort.height))?;
        state.delete(&aft_bulletin_availability_certificate_key(abort.height))?;
        state.delete(&aft_canonical_bulletin_close_key(abort.height))?;
        state.delete(&aft_publication_frontier_key(abort.height))?;

        if let Some(mut collapse) = Self::load_canonical_collapse_object(state, abort.height)
            .map_err(TransactionError::State)?
        {
            collapse.ordering.kind = CanonicalCollapseKind::Abort;
            if abort.bulletin_commitment_hash != [0u8; 32] {
                collapse.ordering.bulletin_commitment_hash = abort.bulletin_commitment_hash;
            }
            if abort.bulletin_availability_certificate_hash != [0u8; 32] {
                collapse.ordering.bulletin_availability_certificate_hash =
                    abort.bulletin_availability_certificate_hash;
            }
            if abort.bulletin_close_hash != [0u8; 32] {
                collapse.ordering.bulletin_close_hash = abort.bulletin_close_hash;
            }
            if abort.canonical_order_certificate_hash != [0u8; 32] {
                collapse.ordering.canonical_order_certificate_hash =
                    abort.canonical_order_certificate_hash;
            }
            let previous = if collapse.height <= 1 {
                None
            } else {
                Self::load_canonical_collapse_object(state, collapse.height - 1)
                    .map_err(TransactionError::State)?
            };
            bind_canonical_collapse_continuity(&mut collapse, previous.as_ref())
                .map_err(TransactionError::Invalid)?;
            state.insert(
                &aft_canonical_collapse_object_key(collapse.height),
                &codec::to_bytes_canonical(&collapse).map_err(TransactionError::Serialization)?,
            )?;
        }
        Ok(())
    }

    fn materialize_canonical_collapse_object(
        state: &mut dyn StateAccess,
        collapse: CanonicalCollapseObject,
    ) -> Result<(), TransactionError> {
        if collapse.height == 0 {
            return Err(TransactionError::Invalid(
                "aft canonical collapse object requires non-zero height".into(),
            ));
        }
        if collapse.ordering.height != collapse.height {
            return Err(TransactionError::Invalid(
                "aft canonical collapse object ordering height must match slot height".into(),
            ));
        }
        if collapse.transactions_root_hash == [0u8; 32]
            || collapse.resulting_state_root_hash == [0u8; 32]
        {
            return Err(TransactionError::Invalid(
                "aft canonical collapse object requires non-zero transaction and state roots"
                    .into(),
            ));
        }
        if let Some(sealing) = collapse.sealing.as_ref() {
            if sealing.height != collapse.height {
                return Err(TransactionError::Invalid(
                    "aft canonical collapse object sealing height must match slot height".into(),
                ));
            }
        }
        Self::validate_canonical_collapse_archived_history_anchor(state, &collapse)?;
        match collapse.ordering.kind {
            CanonicalCollapseKind::Close => {
                if Self::load_canonical_order_abort(state, collapse.height)?.is_some() {
                    return Err(TransactionError::Invalid(
                        "cannot publish a close-valued canonical collapse object after canonical-order abort publication".into(),
                    ));
                }
            }
            CanonicalCollapseKind::Abort => {
                state.delete(&aft_order_certificate_key(collapse.height))?;
                state.delete(&aft_bulletin_availability_certificate_key(collapse.height))?;
                state.delete(&aft_canonical_bulletin_close_key(collapse.height))?;
            }
        }
        if let Some(existing) = Self::load_canonical_collapse_object(state, collapse.height)? {
            let existing_has_abort = existing.ordering.kind == CanonicalCollapseKind::Abort
                || existing
                    .sealing
                    .as_ref()
                    .map(|sealing| sealing.kind == CanonicalCollapseKind::Abort)
                    .unwrap_or(false);
            let new_has_abort = collapse.ordering.kind == CanonicalCollapseKind::Abort
                || collapse
                    .sealing
                    .as_ref()
                    .map(|sealing| sealing.kind == CanonicalCollapseKind::Abort)
                    .unwrap_or(false);
            let anchor_only_upgrade =
                canonical_collapse_eq_ignoring_archived_recovered_history_anchor(
                    &existing, &collapse,
                ) && canonical_collapse_archived_recovered_history_anchor(&existing)
                    .map_err(TransactionError::Invalid)?
                    .is_none()
                    && canonical_collapse_archived_recovered_history_anchor(&collapse)
                        .map_err(TransactionError::Invalid)?
                        .is_some();
            if existing != collapse
                && !(new_has_abort && !existing_has_abort)
                && !anchor_only_upgrade
            {
                return Err(TransactionError::Invalid(
                    "conflicting canonical collapse object already published for height".into(),
                ));
            }
            if existing == collapse {
                return Ok(());
            }
        }
        let previous = if collapse.height <= 1 {
            None
        } else {
            Self::load_canonical_collapse_object(state, collapse.height - 1)?
        };
        verify_canonical_collapse_continuity(&collapse, previous.as_ref())
            .map_err(TransactionError::Invalid)?;
        state.insert(
            &aft_canonical_collapse_object_key(collapse.height),
            &codec::to_bytes_canonical(&collapse).map_err(TransactionError::Serialization)?,
        )?;
        Ok(())
    }

    fn materialize_publication_frontier_contradiction(
        state: &mut dyn StateAccess,
        contradiction: PublicationFrontierContradiction,
    ) -> Result<(), TransactionError> {
        verify_publication_frontier_contradiction(&contradiction)
            .map_err(TransactionError::Invalid)?;
        state.insert(
            &aft_publication_frontier_contradiction_key(contradiction.height),
            &codec::to_bytes_canonical(&contradiction).map_err(TransactionError::Serialization)?,
        )?;
        let (reason, details) = match contradiction.kind {
            PublicationFrontierContradictionKind::ConflictingFrontier => (
                CanonicalOrderAbortReason::PublicationFrontierConflict,
                "published compact publication frontier conflicts with an existing same-slot frontier",
            ),
            PublicationFrontierContradictionKind::StaleParentLink => (
                CanonicalOrderAbortReason::PublicationFrontierStale,
                "published compact publication frontier does not extend the previous frontier",
            ),
        };
        let abort =
            Self::build_canonical_order_abort(contradiction.height, reason, details, None, None);
        Self::materialize_canonical_order_abort(state, abort)
    }

    fn materialize_observer_abort(
        state: &mut dyn StateAccess,
        abort: AsymptoteObserverCanonicalAbort,
    ) -> Result<(), TransactionError> {
        state.delete(&guardian_registry_observer_canonical_close_key(
            abort.epoch,
            abort.height,
            abort.view,
        ))?;
        state.insert(
            &guardian_registry_observer_canonical_abort_key(abort.epoch, abort.height, abort.view),
            &codec::to_bytes_canonical(&abort).map_err(TransactionError::Serialization)?,
        )?;

        if let Some(mut collapse) = Self::load_canonical_collapse_object(state, abort.height)
            .map_err(TransactionError::State)?
        {
            if let Some(sealing) = collapse.sealing.as_mut() {
                if sealing.epoch == abort.epoch
                    && sealing.height == abort.height
                    && sealing.view == abort.view
                {
                    sealing.kind = CanonicalCollapseKind::Abort;
                    sealing.finality_tier = FinalityTier::BaseFinal;
                    sealing.collapse_state = CollapseState::Abort;
                    sealing.transcripts_root = abort.transcripts_root;
                    sealing.challenges_root = abort.challenges_root;
                    sealing.resolution_hash =
                        canonical_asymptote_observer_canonical_abort_hash(&abort)
                            .map_err(TransactionError::Invalid)?;
                    let previous = if collapse.height <= 1 {
                        None
                    } else {
                        Self::load_canonical_collapse_object(state, collapse.height - 1)
                            .map_err(TransactionError::State)?
                    };
                    bind_canonical_collapse_continuity(&mut collapse, previous.as_ref())
                        .map_err(TransactionError::Invalid)?;
                    state.insert(
                        &aft_canonical_collapse_object_key(collapse.height),
                        &codec::to_bytes_canonical(&collapse)
                            .map_err(TransactionError::Serialization)?,
                    )?;
                }
            }
        }
        Ok(())
    }

    fn materialize_canonical_order_publication_bundle(
        &self,
        state: &mut dyn StateAccess,
        bundle: &CanonicalOrderPublicationBundle,
        bulletin_close: &CanonicalBulletinClose,
        ctx: &mut TxContext<'_>,
    ) -> Result<(), TransactionError> {
        if bundle
            .canonical_order_certificate
            .omission_proofs
            .is_empty()
            && Self::load_canonical_order_abort(state, bundle.canonical_order_certificate.height)?
                .is_some()
        {
            return Err(TransactionError::Invalid(
                "cannot admit a positive canonical-order bundle after canonical abort publication"
                    .into(),
            ));
        }

        state.insert(
            &aft_bulletin_commitment_key(bundle.bulletin_commitment.height),
            &codec::to_bytes_canonical(&bundle.bulletin_commitment)
                .map_err(TransactionError::Serialization)?,
        )?;
        for entry in &bundle.bulletin_entries {
            state.insert(
                &aft_bulletin_entry_key(entry.height, &entry.tx_hash),
                &codec::to_bytes_canonical(entry).map_err(TransactionError::Serialization)?,
            )?;
        }
        if !bundle
            .canonical_order_certificate
            .omission_proofs
            .is_empty()
        {
            for omission in &bundle.canonical_order_certificate.omission_proofs {
                if omission.offender_account_id == AccountId::default() {
                    return Err(TransactionError::Invalid(
                        "aft omission proof requires a non-zero accountable offender".into(),
                    ));
                }
                state.insert(
                    &aft_omission_proof_key(
                        bundle.canonical_order_certificate.height,
                        &omission.tx_hash,
                    ),
                    &codec::to_bytes_canonical(omission)
                        .map_err(TransactionError::Serialization)?,
                )?;
                let report = Self::omission_failure_report(omission)?;
                Self::apply_accountable_fault_report(
                    state,
                    report,
                    ctx.block_height,
                    self.config.apply_accountable_membership_updates,
                )?;
            }
            let abort = Self::build_canonical_order_abort(
                bundle.canonical_order_certificate.height,
                CanonicalOrderAbortReason::OmissionDominated,
                "objective omission proofs dominate the candidate canonical order",
                Some(&bundle.canonical_order_certificate),
                Some(bulletin_close),
            );
            Self::materialize_canonical_order_abort(state, abort)?;
            return Ok(());
        }
        state.insert(
            &aft_bulletin_availability_certificate_key(
                bundle.bulletin_availability_certificate.height,
            ),
            &codec::to_bytes_canonical(&bundle.bulletin_availability_certificate)
                .map_err(TransactionError::Serialization)?,
        )?;
        state.insert(
            &aft_order_certificate_key(bundle.canonical_order_certificate.height),
            &codec::to_bytes_canonical(&bundle.canonical_order_certificate)
                .map_err(TransactionError::Serialization)?,
        )?;
        state.insert(
            &aft_canonical_bulletin_close_key(bundle.canonical_order_certificate.height),
            &codec::to_bytes_canonical(bulletin_close).map_err(TransactionError::Serialization)?,
        )?;
        Ok(())
    }

    fn materialize_recovery_impossible_abort_if_needed(
        state: &mut dyn StateAccess,
        height: u64,
    ) -> Result<(), TransactionError> {
        if Self::load_canonical_bulletin_close(state, height)
            .map_err(TransactionError::State)?
            .is_some()
            || Self::load_canonical_order_abort(state, height)
                .map_err(TransactionError::State)?
                .is_some()
        {
            return Ok(());
        }

        let Some(capsule) =
            Self::load_recovery_capsule(state, height).map_err(TransactionError::State)?
        else {
            return Ok(());
        };
        let certificates = Self::load_recovery_witness_certificates(state, height)
            .map_err(TransactionError::State)?;
        if certificates.is_empty() {
            return Ok(());
        }
        let expected_witness_manifest_hashes = certificates
            .iter()
            .map(|certificate| certificate.witness_manifest_hash)
            .collect::<Vec<_>>();
        match Self::load_recovery_threshold_status(
            state,
            height,
            &expected_witness_manifest_hashes,
            capsule.coding.recovery_threshold,
        )
        .map_err(TransactionError::State)?
        {
            RecoveryThresholdStatus::Impossible => {
                let abort = Self::build_canonical_order_abort(
                    height,
                    CanonicalOrderAbortReason::RecoveryThresholdImpossible,
                    "published recovery receipts and missingness make threshold reconstruction impossible",
                    None,
                    None,
                );
                Self::materialize_canonical_order_abort(state, abort)
            }
            RecoveryThresholdStatus::Pending | RecoveryThresholdStatus::Recoverable(_) => Ok(()),
        }
    }

    fn recovered_publication_bundle_conflicts(
        existing: &RecoveredPublicationBundle,
        candidate: &RecoveredPublicationBundle,
    ) -> bool {
        existing.height == candidate.height
            && (existing.block_commitment_hash != candidate.block_commitment_hash
                || existing.recoverable_slot_payload_hash
                    != candidate.recoverable_slot_payload_hash
                || existing.canonical_order_publication_bundle_hash
                    != candidate.canonical_order_publication_bundle_hash
                || existing.canonical_bulletin_close_hash
                    != candidate.canonical_bulletin_close_hash)
    }

    fn refresh_observer_challenge_surface(
        state: &mut dyn StateAccess,
        challenge: &AsymptoteObserverChallenge,
    ) -> Result<(), TransactionError> {
        let challenges = Self::load_observer_challenges(
            state,
            challenge.epoch,
            challenge.height,
            challenge.view,
        )
        .map_err(TransactionError::State)?;
        let challenges_root = canonical_asymptote_observer_challenges_hash(&challenges)
            .map_err(TransactionError::Invalid)?;
        let challenge_count = u16::try_from(challenges.len()).map_err(|_| {
            TransactionError::Invalid("observer challenge count exceeds u16".into())
        })?;
        let challenge_commitment = AsymptoteObserverChallengeCommitment {
            epoch: challenge.epoch,
            height: challenge.height,
            view: challenge.view,
            challenges_root,
            challenge_count,
        };
        state.insert(
            &guardian_registry_observer_challenge_commitment_key(
                challenge.epoch,
                challenge.height,
                challenge.view,
            ),
            &codec::to_bytes_canonical(&challenge_commitment)
                .map_err(TransactionError::Serialization)?,
        )?;

        let abort_basis = challenge
            .canonical_close
            .clone()
            .map(|close| {
                (
                    close.assignments_hash,
                    close.transcripts_root,
                    close.transcript_count,
                    close.challenge_cutoff_timestamp_ms,
                )
            })
            .or_else(|| {
                Self::load_asymptote_observer_canonical_close(
                    state,
                    challenge.epoch,
                    challenge.height,
                    challenge.view,
                )
                .ok()
                .flatten()
                .map(|close| {
                    (
                        close.assignments_hash,
                        close.transcripts_root,
                        close.transcript_count,
                        close.challenge_cutoff_timestamp_ms,
                    )
                })
            })
            .or_else(|| {
                Self::load_asymptote_observer_canonical_abort(
                    state,
                    challenge.epoch,
                    challenge.height,
                    challenge.view,
                )
                .ok()
                .flatten()
                .map(|abort| {
                    (
                        abort.assignments_hash,
                        abort.transcripts_root,
                        abort.transcript_count,
                        abort.challenge_cutoff_timestamp_ms,
                    )
                })
            });

        if let Some((
            assignments_hash,
            transcripts_root,
            transcript_count,
            challenge_cutoff_timestamp_ms,
        )) = abort_basis
        {
            Self::materialize_observer_abort(
                state,
                AsymptoteObserverCanonicalAbort {
                    epoch: challenge.epoch,
                    height: challenge.height,
                    view: challenge.view,
                    assignments_hash,
                    transcripts_root,
                    challenges_root,
                    transcript_count,
                    challenge_count,
                    challenge_cutoff_timestamp_ms,
                },
            )?;
        }

        Ok(())
    }

    fn observation_request_producer_account(
        challenge: &AsymptoteObserverChallenge,
    ) -> Option<AccountId> {
        challenge
            .assignment
            .as_ref()
            .map(|assignment| assignment.producer_account_id)
            .or_else(|| {
                challenge
                    .observation_request
                    .as_ref()
                    .map(|request| request.assignment.producer_account_id)
            })
            .or_else(|| {
                challenge
                    .transcript
                    .as_ref()
                    .map(|transcript| transcript.statement.assignment.producer_account_id)
            })
    }

    fn observation_request_observer_account(
        challenge: &AsymptoteObserverChallenge,
    ) -> Option<AccountId> {
        challenge
            .assignment
            .as_ref()
            .map(|assignment| assignment.observer_account_id)
            .or_else(|| {
                challenge
                    .observation_request
                    .as_ref()
                    .map(|request| request.assignment.observer_account_id)
            })
            .or_else(|| {
                challenge
                    .transcript
                    .as_ref()
                    .map(|transcript| transcript.statement.assignment.observer_account_id)
            })
    }

    fn accountable_challenge_offender(challenge: &AsymptoteObserverChallenge) -> Option<AccountId> {
        match challenge.kind {
            AsymptoteObserverChallengeKind::MissingTranscript
            | AsymptoteObserverChallengeKind::ConflictingTranscript => {
                Self::observation_request_observer_account(challenge)
            }
            AsymptoteObserverChallengeKind::TranscriptMismatch
            | AsymptoteObserverChallengeKind::VetoTranscriptPresent => {
                Self::observation_request_producer_account(challenge)
            }
            AsymptoteObserverChallengeKind::InvalidCanonicalClose => {
                Self::observation_request_producer_account(challenge)
                    .or_else(|| Some(challenge.challenger_account_id))
            }
        }
    }

    fn omission_failure_report(
        omission: &OmissionProof,
    ) -> Result<FailureReport, TransactionError> {
        let proof = codec::to_bytes_canonical(omission).map_err(TransactionError::Serialization)?;
        Ok(FailureReport {
            offender: omission.offender_account_id,
            offense_type: OffenseType::AftOrderingOmission,
            facts: OffenseFacts::AftOrderingOmission {
                height: omission.height,
                tx_hash: omission.tx_hash,
                bulletin_root: omission.bulletin_root,
            },
            proof,
        })
    }

    fn observer_challenge_failure_report(
        challenge: &AsymptoteObserverChallenge,
    ) -> Result<Option<FailureReport>, TransactionError> {
        let Some(offender) = Self::accountable_challenge_offender(challenge) else {
            return Ok(None);
        };
        let proof =
            codec::to_bytes_canonical(challenge).map_err(TransactionError::Serialization)?;
        Ok(Some(FailureReport {
            offender,
            offense_type: OffenseType::AftObserverChallenge,
            facts: OffenseFacts::AftObserverChallenge {
                challenge_id: challenge.challenge_id,
                epoch: challenge.epoch,
                height: challenge.height,
                view: challenge.view,
                kind: challenge.kind,
                evidence_hash: challenge.evidence_hash,
            },
            proof,
        }))
    }

    fn validate_observer_challenge_shape(
        challenge: &AsymptoteObserverChallenge,
    ) -> Result<(), TransactionError> {
        match challenge.kind {
            AsymptoteObserverChallengeKind::MissingTranscript => {
                let assignment = challenge.assignment.as_ref().ok_or_else(|| {
                    TransactionError::Invalid(
                        "missing-transcript challenge must carry an assignment".into(),
                    )
                })?;
                if challenge.observation_request.is_some()
                    || challenge.transcript.is_some()
                    || challenge.canonical_close.is_some()
                {
                    return Err(TransactionError::Invalid(
                        "missing-transcript challenge may only carry assignment evidence".into(),
                    ));
                }
                let expected_hash = canonical_asymptote_observer_assignment_hash(assignment)
                    .map_err(TransactionError::Invalid)?;
                if challenge.evidence_hash != expected_hash {
                    return Err(TransactionError::Invalid(
                        "missing-transcript challenge evidence hash does not match the assignment"
                            .into(),
                    ));
                }
            }
            AsymptoteObserverChallengeKind::TranscriptMismatch => {
                let request = challenge.observation_request.as_ref().ok_or_else(|| {
                    TransactionError::Invalid(
                        "transcript-mismatch challenge must carry an observation request".into(),
                    )
                })?;
                if challenge.assignment.is_none()
                    || challenge.transcript.is_some()
                    || challenge.canonical_close.is_some()
                {
                    return Err(TransactionError::Invalid(
                        "transcript-mismatch challenge must carry only assignment and observation-request evidence".into(),
                    ));
                }
                let expected_hash = canonical_asymptote_observer_observation_request_hash(request)
                    .map_err(TransactionError::Invalid)?;
                if challenge.evidence_hash != expected_hash {
                    return Err(TransactionError::Invalid(
                        "transcript-mismatch challenge evidence hash does not match the offending request".into(),
                    ));
                }
            }
            AsymptoteObserverChallengeKind::VetoTranscriptPresent
            | AsymptoteObserverChallengeKind::ConflictingTranscript => {
                let transcript = challenge.transcript.as_ref().ok_or_else(|| {
                    TransactionError::Invalid(
                        "transcript-based observer challenge must carry a transcript".into(),
                    )
                })?;
                if challenge.assignment.is_none()
                    || challenge.observation_request.is_some()
                    || challenge.canonical_close.is_some()
                {
                    return Err(TransactionError::Invalid(
                        "transcript-based observer challenge must carry only assignment and transcript evidence".into(),
                    ));
                }
                let expected_hash = canonical_asymptote_observer_transcript_hash(transcript)
                    .map_err(TransactionError::Invalid)?;
                if challenge.evidence_hash != expected_hash {
                    return Err(TransactionError::Invalid(
                        "observer challenge evidence hash does not match the offending transcript"
                            .into(),
                    ));
                }
            }
            AsymptoteObserverChallengeKind::InvalidCanonicalClose => {
                let close = challenge.canonical_close.as_ref().ok_or_else(|| {
                    TransactionError::Invalid(
                        "invalid-canonical-close challenge must carry the offending canonical close"
                            .into(),
                    )
                })?;
                if challenge.assignment.is_some()
                    || challenge.observation_request.is_some()
                    || challenge.transcript.is_some()
                {
                    return Err(TransactionError::Invalid(
                        "invalid-canonical-close challenge may only carry canonical-close evidence"
                            .into(),
                    ));
                }
                let expected_hash = canonical_asymptote_observer_canonical_close_hash(close)
                    .map_err(TransactionError::Invalid)?;
                if challenge.evidence_hash != expected_hash {
                    return Err(TransactionError::Invalid(
                        "invalid-canonical-close challenge evidence hash does not match the offending close".into(),
                    ));
                }
            }
        }
        Ok(())
    }

    fn apply_accountable_membership_updates(
        state: &mut dyn StateAccess,
        offender: AccountId,
        block_height: u64,
    ) -> Result<(), TransactionError> {
        let Some(validator_set_bytes) = state.get(VALIDATOR_SET_KEY)? else {
            return Ok(());
        };
        let mut sets =
            read_validator_sets(&validator_set_bytes).map_err(TransactionError::State)?;
        let active_set = effective_set_for_height(&sets, block_height).clone();

        let active_accounts = active_set
            .validators
            .iter()
            .map(|validator| validator.account_id)
            .collect::<Vec<_>>();

        let mut quarantined = Self::load_quarantined_validators(state)?;
        if active_accounts.contains(&offender) && !quarantined.contains(&offender) {
            let live_after = active_accounts
                .len()
                .saturating_sub(quarantined.len())
                .saturating_sub(1);
            if live_after >= 2 {
                quarantined.insert(offender);
                state.insert(
                    QUARANTINED_VALIDATORS_KEY,
                    &codec::to_bytes_canonical(&quarantined)
                        .map_err(TransactionError::Serialization)?,
                )?;
            }
        }

        let mut staged_next = match sets.next.clone() {
            Some(next) if next.effective_from_height > block_height => next,
            _ => {
                let mut next = active_set.clone();
                next.effective_from_height = block_height.saturating_add(1);
                next
            }
        };
        if staged_next.validators.len() <= 1 {
            return Ok(());
        }

        let original_len = staged_next.validators.len();
        staged_next
            .validators
            .retain(|validator| validator.account_id != offender);
        if staged_next.validators.len() == original_len {
            return Ok(());
        }

        staged_next.total_weight = staged_next
            .validators
            .iter()
            .map(|validator| validator.weight)
            .sum();
        sets.next = Some(staged_next);
        state.insert(
            VALIDATOR_SET_KEY,
            &write_validator_sets(&sets).map_err(TransactionError::State)?,
        )?;
        Ok(())
    }

    fn apply_accountable_fault_report(
        state: &mut dyn StateAccess,
        report: FailureReport,
        block_height: u64,
        apply_membership_updates: bool,
    ) -> Result<(), TransactionError> {
        let evidence_key =
            evidence_id(&report).map_err(|error| TransactionError::Invalid(error.to_string()))?;
        let mut evidence_registry = Self::load_evidence_registry(state)?;
        if !evidence_registry.insert(evidence_key) {
            return Ok(());
        }

        state.insert(
            EVIDENCE_REGISTRY_KEY,
            &codec::to_bytes_canonical(&evidence_registry)
                .map_err(TransactionError::Serialization)?,
        )?;
        if !apply_membership_updates {
            return Ok(());
        }
        if let Err(error) =
            Self::apply_accountable_membership_updates(state, report.offender, block_height)
        {
            warn!(
                offender = ?report.offender,
                block_height,
                error = %error,
                "accountable membership updates failed after evidence publication; leaving negative object decisive"
            );
        }
        Ok(())
    }

    pub fn load_asymptote_observer_transcript_commitment(
        state: &dyn StateAccess,
        epoch: u64,
        height: u64,
        view: u64,
    ) -> Result<Option<AsymptoteObserverTranscriptCommitment>, StateError> {
        match state.get(&guardian_registry_observer_transcript_commitment_key(
            epoch, height, view,
        ))? {
            Some(bytes) => codec::from_bytes_canonical(&bytes)
                .map(Some)
                .map_err(|e| StateError::InvalidValue(e.to_string())),
            None => Ok(None),
        }
    }

    pub fn load_asymptote_observer_challenge_commitment(
        state: &dyn StateAccess,
        epoch: u64,
        height: u64,
        view: u64,
    ) -> Result<Option<AsymptoteObserverChallengeCommitment>, StateError> {
        match state.get(&guardian_registry_observer_challenge_commitment_key(
            epoch, height, view,
        ))? {
            Some(bytes) => codec::from_bytes_canonical(&bytes)
                .map(Some)
                .map_err(|e| StateError::InvalidValue(e.to_string())),
            None => Ok(None),
        }
    }

    pub fn load_asymptote_observer_canonical_close(
        state: &dyn StateAccess,
        epoch: u64,
        height: u64,
        view: u64,
    ) -> Result<Option<AsymptoteObserverCanonicalClose>, StateError> {
        match state.get(&guardian_registry_observer_canonical_close_key(
            epoch, height, view,
        ))? {
            Some(bytes) => codec::from_bytes_canonical(&bytes)
                .map(Some)
                .map_err(|e| StateError::InvalidValue(e.to_string())),
            None => Ok(None),
        }
    }

    pub fn load_asymptote_observer_canonical_abort(
        state: &dyn StateAccess,
        epoch: u64,
        height: u64,
        view: u64,
    ) -> Result<Option<AsymptoteObserverCanonicalAbort>, StateError> {
        match state.get(&guardian_registry_observer_canonical_abort_key(
            epoch, height, view,
        ))? {
            Some(bytes) => codec::from_bytes_canonical(&bytes)
                .map(Some)
                .map_err(|e| StateError::InvalidValue(e.to_string())),
            None => Ok(None),
        }
    }

    pub fn load_sealed_effect_record(
        state: &dyn StateAccess,
        intent_hash: &[u8; 32],
    ) -> Result<Option<SealedEffectRecord>, StateError> {
        match state.get(&guardian_registry_sealed_effect_key(intent_hash))? {
            Some(bytes) => codec::from_bytes_canonical(&bytes)
                .map(Some)
                .map_err(|e| StateError::InvalidValue(e.to_string())),
            None => Ok(None),
        }
    }

    fn validate_diversity(
        labels: impl Iterator<Item = Option<String>>,
        minimum: u16,
        field: &str,
    ) -> Result<(), TransactionError> {
        if minimum == 0 {
            return Ok(());
        }

        let distinct = labels
            .flatten()
            .filter(|value| !value.trim().is_empty())
            .collect::<BTreeSet<_>>();

        if distinct.len() < usize::from(minimum) {
            return Err(TransactionError::Invalid(format!(
                "guardian registry policy requires at least {} distinct {} labels, got {}",
                minimum,
                field,
                distinct.len()
            )));
        }
        Ok(())
    }

    fn validate_committee_manifest(
        &self,
        manifest: &GuardianCommitteeManifest,
    ) -> Result<(), TransactionError> {
        let member_count = manifest.members.len();
        if member_count < usize::from(self.config.minimum_committee_size) {
            return Err(TransactionError::Invalid(format!(
                "guardian committee size {} is below minimum {}",
                member_count, self.config.minimum_committee_size
            )));
        }
        if member_count == 0 {
            return Err(TransactionError::Invalid(
                "guardian committee must contain at least one member".into(),
            ));
        }
        if manifest.threshold == 0 || usize::from(manifest.threshold) > member_count {
            return Err(TransactionError::Invalid(format!(
                "guardian committee threshold {} is invalid for size {}",
                manifest.threshold, member_count
            )));
        }
        if usize::from(manifest.threshold) <= member_count / 2 {
            return Err(TransactionError::Invalid(
                "guardian committee threshold must be a strict majority".into(),
            ));
        }
        if self.config.require_even_committee_sizes && member_count % 2 != 0 {
            return Err(TransactionError::Invalid(
                "production guardian committees must be even-sized in registry policy".into(),
            ));
        }
        if self.config.require_checkpoint_anchoring
            && manifest.transparency_log_id.trim().is_empty()
        {
            return Err(TransactionError::Invalid(
                "guardian committee must declare a transparency log id".into(),
            ));
        }

        Self::validate_diversity(
            manifest
                .members
                .iter()
                .map(|member| member.provider.clone()),
            self.config.minimum_provider_diversity,
            "provider",
        )?;
        Self::validate_diversity(
            manifest.members.iter().map(|member| member.region.clone()),
            self.config.minimum_region_diversity,
            "region",
        )?;
        Self::validate_diversity(
            manifest
                .members
                .iter()
                .map(|member| member.host_class.clone()),
            self.config.minimum_host_class_diversity,
            "host class",
        )?;
        Self::validate_diversity(
            manifest
                .members
                .iter()
                .map(|member| member.key_authority_kind.map(|kind| format!("{kind:?}"))),
            self.config.minimum_backend_diversity,
            "key authority",
        )?;

        Ok(())
    }

    fn validate_witness_manifest(
        &self,
        manifest: &GuardianWitnessCommitteeManifest,
    ) -> Result<(), TransactionError> {
        let member_count = manifest.members.len();
        if member_count < usize::from(self.config.minimum_witness_committee_size) {
            return Err(TransactionError::Invalid(format!(
                "witness committee size {} is below minimum {}",
                member_count, self.config.minimum_witness_committee_size
            )));
        }
        if manifest.threshold == 0 || usize::from(manifest.threshold) > member_count {
            return Err(TransactionError::Invalid(format!(
                "witness committee threshold {} is invalid for size {}",
                manifest.threshold, member_count
            )));
        }
        if usize::from(manifest.threshold) <= member_count / 2 {
            return Err(TransactionError::Invalid(
                "witness committee threshold must be a strict majority".into(),
            ));
        }
        if self.config.require_even_committee_sizes && member_count % 2 != 0 {
            return Err(TransactionError::Invalid(
                "production witness committees must be even-sized in registry policy".into(),
            ));
        }
        if self.config.require_checkpoint_anchoring
            && manifest.transparency_log_id.trim().is_empty()
        {
            return Err(TransactionError::Invalid(
                "witness committee must declare a transparency log id".into(),
            ));
        }
        if manifest.stratum_id.trim().is_empty() {
            return Err(TransactionError::Invalid(
                "witness committee must declare a certification stratum".into(),
            ));
        }

        Self::validate_diversity(
            manifest
                .members
                .iter()
                .map(|member| member.provider.clone()),
            self.config.minimum_provider_diversity,
            "provider",
        )?;
        Self::validate_diversity(
            manifest.members.iter().map(|member| member.region.clone()),
            self.config.minimum_region_diversity,
            "region",
        )?;
        Self::validate_diversity(
            manifest
                .members
                .iter()
                .map(|member| member.host_class.clone()),
            self.config.minimum_host_class_diversity,
            "host class",
        )?;
        Self::validate_diversity(
            manifest
                .members
                .iter()
                .map(|member| member.key_authority_kind.map(|kind| format!("{kind:?}"))),
            self.config.minimum_backend_diversity,
            "key authority",
        )?;

        Ok(())
    }

    fn validate_log_descriptor(
        &self,
        descriptor: &GuardianTransparencyLogDescriptor,
    ) -> Result<(), TransactionError> {
        if descriptor.log_id.trim().is_empty() {
            return Err(TransactionError::Invalid(
                "guardian transparency log id must not be empty".into(),
            ));
        }
        if descriptor.public_key.is_empty() {
            return Err(TransactionError::Invalid(
                "guardian transparency log public key must not be empty".into(),
            ));
        }
        Ok(())
    }
}

#[async_trait]
impl BlockchainService for GuardianRegistry {
    fn id(&self) -> &str {
        "guardian_registry"
    }

    fn abi_version(&self) -> u32 {
        1
    }

    fn state_schema(&self) -> &str {
        "guardian_registry/v1"
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities::empty()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    async fn handle_service_call(
        &self,
        state: &mut dyn StateAccess,
        method: &str,
        params: &[u8],
        ctx: &mut TxContext<'_>,
    ) -> Result<(), TransactionError> {
        match method {
            "register_guardian_transparency_log@v1" => {
                let descriptor: GuardianTransparencyLogDescriptor =
                    codec::from_bytes_canonical(params)?;
                self.validate_log_descriptor(&descriptor)?;
                state.insert(
                    &guardian_registry_log_key(&descriptor.log_id),
                    &codec::to_bytes_canonical(&descriptor)
                        .map_err(TransactionError::Serialization)?,
                )?;
                Ok(())
            }
            "register_guardian_committee@v1" => {
                let manifest: GuardianCommitteeManifest = codec::from_bytes_canonical(params)?;
                self.validate_committee_manifest(&manifest)?;
                let manifest_hash = Self::manifest_hash(&manifest)?;
                state.insert(
                    &guardian_registry_committee_key(&manifest_hash),
                    &codec::to_bytes_canonical(&manifest)
                        .map_err(TransactionError::Serialization)?,
                )?;
                state.insert(
                    &guardian_registry_committee_account_key(&manifest.validator_account_id),
                    manifest_hash.as_ref(),
                )?;
                Ok(())
            }
            "publish_measurement_profile@v1" => {
                let profile: GuardianMeasurementProfile = codec::from_bytes_canonical(params)?;
                state.insert(
                    &[
                        GUARDIAN_REGISTRY_MEASUREMENT_PREFIX,
                        profile.profile_id.as_bytes(),
                    ]
                    .concat(),
                    &codec::to_bytes_canonical(&profile)
                        .map_err(TransactionError::Serialization)?,
                )?;
                if profile.profile_id == "default" {
                    state.insert(
                        &[GUARDIAN_REGISTRY_MEASUREMENT_PREFIX, b"default"].concat(),
                        &codec::to_bytes_canonical(&profile)
                            .map_err(TransactionError::Serialization)?,
                    )?;
                }
                Ok(())
            }
            "register_guardian_witness_committee@v1" => {
                let manifest: GuardianWitnessCommitteeManifest =
                    codec::from_bytes_canonical(params)?;
                self.validate_witness_manifest(&manifest)?;
                let manifest_hash = sha256(
                    &codec::to_bytes_canonical(&manifest)
                        .map_err(TransactionError::Serialization)?,
                )
                .map_err(|e| TransactionError::Invalid(e.to_string()))
                .and_then(|digest| {
                    digest.try_into().map_err(|_| {
                        TransactionError::Invalid("invalid witness manifest hash length".into())
                    })
                })?;
                state.insert(
                    &guardian_registry_witness_key(&manifest_hash),
                    &codec::to_bytes_canonical(&manifest)
                        .map_err(TransactionError::Serialization)?,
                )?;
                let active_key = guardian_registry_witness_set_key(manifest.epoch);
                let mut active_set = match state.get(&active_key)? {
                    Some(bytes) => codec::from_bytes_canonical::<GuardianWitnessSet>(&bytes)?,
                    None => GuardianWitnessSet {
                        epoch: manifest.epoch,
                        manifest_hashes: Vec::new(),
                        checkpoint_interval_blocks: 1,
                    },
                };
                if !active_set.manifest_hashes.contains(&manifest_hash) {
                    active_set.manifest_hashes.push(manifest_hash);
                    active_set.manifest_hashes.sort_unstable();
                }
                state.insert(
                    &active_key,
                    &codec::to_bytes_canonical(&active_set)
                        .map_err(TransactionError::Serialization)?,
                )?;
                Ok(())
            }
            "publish_witness_epoch_seed@v1" => {
                let seed: GuardianWitnessEpochSeed = codec::from_bytes_canonical(params)?;
                state.insert(
                    &guardian_registry_witness_seed_key(seed.epoch),
                    &codec::to_bytes_canonical(&seed).map_err(TransactionError::Serialization)?,
                )?;
                let active_key = guardian_registry_witness_set_key(seed.epoch);
                let mut active_set = match state.get(&active_key)? {
                    Some(bytes) => codec::from_bytes_canonical::<GuardianWitnessSet>(&bytes)?,
                    None => GuardianWitnessSet {
                        epoch: seed.epoch,
                        manifest_hashes: Vec::new(),
                        checkpoint_interval_blocks: seed.checkpoint_interval_blocks,
                    },
                };
                active_set.checkpoint_interval_blocks = seed.checkpoint_interval_blocks;
                state.insert(
                    &active_key,
                    &codec::to_bytes_canonical(&active_set)
                        .map_err(TransactionError::Serialization)?,
                )?;
                Ok(())
            }
            "publish_asymptote_policy@v1" => {
                let policy: AsymptotePolicy = codec::from_bytes_canonical(params)?;
                let witness_mode = !policy.required_witness_strata.is_empty()
                    || !policy.escalation_witness_strata.is_empty();
                let observer_mode =
                    policy.observer_rounds > 0 || policy.observer_committee_size > 0;
                if !witness_mode && !observer_mode {
                    return Err(TransactionError::Invalid(
                        "asymptote policy requires either witness strata or equal-authority observer sampling".into(),
                    ));
                }
                if observer_mode
                    && (policy.observer_rounds == 0 || policy.observer_committee_size == 0)
                {
                    return Err(TransactionError::Invalid(
                        "asymptote equal-authority observer mode requires non-zero rounds and committee size".into(),
                    ));
                }
                if matches!(
                    policy.observer_sealing_mode,
                    AsymptoteObserverSealingMode::CanonicalChallengeV1
                ) && !observer_mode
                {
                    return Err(TransactionError::Invalid(
                        "canonical observer sealing mode requires equal-authority observer assignments"
                            .into(),
                    ));
                }
                if matches!(
                    policy.observer_sealing_mode,
                    AsymptoteObserverSealingMode::CanonicalChallengeV1
                ) && policy.observer_challenge_window_ms == 0
                {
                    return Err(TransactionError::Invalid(
                        "canonical observer sealing mode requires a non-zero challenge window"
                            .into(),
                    ));
                }
                if witness_mode {
                    if policy.required_witness_strata.is_empty() {
                        return Err(TransactionError::Invalid(
                            "asymptote witness mode requires at least one base witness stratum"
                                .into(),
                        ));
                    }
                    let required = policy
                        .required_witness_strata
                        .iter()
                        .map(|stratum| stratum.trim())
                        .collect::<std::collections::BTreeSet<_>>();
                    let escalation = policy
                        .escalation_witness_strata
                        .iter()
                        .map(|stratum| stratum.trim())
                        .collect::<std::collections::BTreeSet<_>>();
                    if required.contains("") || escalation.contains("") {
                        return Err(TransactionError::Invalid(
                            "asymptote witness strata must not be empty".into(),
                        ));
                    }
                    if required.len() != policy.required_witness_strata.len()
                        || escalation.len() != policy.escalation_witness_strata.len()
                    {
                        return Err(TransactionError::Invalid(
                            "asymptote witness strata must be unique".into(),
                        ));
                    }
                    if !required.is_subset(&escalation) {
                        return Err(TransactionError::Invalid(
                            "asymptote escalation strata must include all base strata".into(),
                        ));
                    }
                }
                if policy.max_checkpoint_staleness_ms > 0
                    && policy.max_checkpoint_staleness_ms < self.config.max_checkpoint_staleness_ms
                {
                    return Err(TransactionError::Invalid(
                        "asymptote checkpoint staleness cannot be weaker than guardian registry policy"
                            .into(),
                    ));
                }
                state.insert(
                    &guardian_registry_asymptote_policy_key(policy.epoch),
                    &codec::to_bytes_canonical(&policy).map_err(TransactionError::Serialization)?,
                )?;
                Ok(())
            }
            "publish_asymptote_observer_transcript_commitment@v1" => {
                let commitment: AsymptoteObserverTranscriptCommitment =
                    codec::from_bytes_canonical(params)?;
                if commitment.epoch == 0 || commitment.height == 0 {
                    return Err(TransactionError::Invalid(
                        "observer transcript commitment requires non-zero epoch and height".into(),
                    ));
                }
                state.insert(
                    &guardian_registry_observer_transcript_commitment_key(
                        commitment.epoch,
                        commitment.height,
                        commitment.view,
                    ),
                    &codec::to_bytes_canonical(&commitment)
                        .map_err(TransactionError::Serialization)?,
                )?;
                Ok(())
            }
            "publish_asymptote_observer_transcript@v1" => {
                let transcript: AsymptoteObserverTranscript = codec::from_bytes_canonical(params)?;
                if transcript.statement.epoch == 0 || transcript.statement.assignment.height == 0 {
                    return Err(TransactionError::Invalid(
                        "observer transcript requires non-zero epoch and height".into(),
                    ));
                }
                state.insert(
                    &guardian_registry_observer_transcript_key(
                        transcript.statement.epoch,
                        transcript.statement.assignment.height,
                        transcript.statement.assignment.view,
                        transcript.statement.assignment.round,
                        &transcript.statement.assignment.observer_account_id,
                    ),
                    &codec::to_bytes_canonical(&transcript)
                        .map_err(TransactionError::Serialization)?,
                )?;
                Ok(())
            }
            "publish_asymptote_observer_challenge_commitment@v1" => {
                let commitment: AsymptoteObserverChallengeCommitment =
                    codec::from_bytes_canonical(params)?;
                if commitment.epoch == 0 || commitment.height == 0 {
                    return Err(TransactionError::Invalid(
                        "observer challenge commitment requires non-zero epoch and height".into(),
                    ));
                }
                state.insert(
                    &guardian_registry_observer_challenge_commitment_key(
                        commitment.epoch,
                        commitment.height,
                        commitment.view,
                    ),
                    &codec::to_bytes_canonical(&commitment)
                        .map_err(TransactionError::Serialization)?,
                )?;
                Ok(())
            }
            "report_asymptote_observer_challenge@v1" => {
                let challenge: AsymptoteObserverChallenge = codec::from_bytes_canonical(params)?;
                if challenge.epoch == 0
                    || challenge.height == 0
                    || challenge.challenge_id == [0u8; 32]
                {
                    return Err(TransactionError::Invalid(
                        "observer challenge requires non-zero epoch, height, and challenge id"
                            .into(),
                    ));
                }
                Self::validate_observer_challenge_shape(&challenge)?;
                state.insert(
                    &guardian_registry_observer_challenge_key(
                        challenge.epoch,
                        challenge.height,
                        challenge.view,
                        &challenge.challenge_id,
                    ),
                    &codec::to_bytes_canonical(&challenge)
                        .map_err(TransactionError::Serialization)?,
                )?;
                Self::refresh_observer_challenge_surface(state, &challenge)?;
                if let Some(report) = Self::observer_challenge_failure_report(&challenge)? {
                    Self::apply_accountable_fault_report(
                        state,
                        report,
                        ctx.block_height,
                        self.config.apply_accountable_membership_updates,
                    )?;
                }
                Ok(())
            }
            "publish_asymptote_observer_canonical_close@v1" => {
                let close: AsymptoteObserverCanonicalClose = codec::from_bytes_canonical(params)?;
                if close.epoch == 0 || close.height == 0 {
                    return Err(TransactionError::Invalid(
                        "observer canonical close requires non-zero epoch and height".into(),
                    ));
                }
                if let Some(existing_abort) = Self::load_asymptote_observer_canonical_abort(
                    state,
                    close.epoch,
                    close.height,
                    close.view,
                )? {
                    return Err(TransactionError::Invalid(format!(
                        "cannot publish observer canonical close after canonical abort is already persisted for {}/{}/{}",
                        existing_abort.epoch, existing_abort.height, existing_abort.view
                    )));
                }
                if let Some(existing_commitment) =
                    Self::load_asymptote_observer_challenge_commitment(
                        state,
                        close.epoch,
                        close.height,
                        close.view,
                    )?
                {
                    if existing_commitment.challenge_count > 0 {
                        return Err(TransactionError::Invalid(
                            "cannot publish observer canonical close once the stored challenge surface is non-empty"
                                .into(),
                        ));
                    }
                }
                if let Some(existing_close) = Self::load_asymptote_observer_canonical_close(
                    state,
                    close.epoch,
                    close.height,
                    close.view,
                )? {
                    if existing_close != close {
                        return Err(TransactionError::Invalid(
                            "conflicting observer canonical close already published for slot"
                                .into(),
                        ));
                    }
                    return Ok(());
                }
                state.insert(
                    &guardian_registry_observer_canonical_close_key(
                        close.epoch,
                        close.height,
                        close.view,
                    ),
                    &codec::to_bytes_canonical(&close).map_err(TransactionError::Serialization)?,
                )?;
                Ok(())
            }
            "publish_asymptote_observer_canonical_abort@v1" => {
                let abort: AsymptoteObserverCanonicalAbort = codec::from_bytes_canonical(params)?;
                if abort.epoch == 0 || abort.height == 0 {
                    return Err(TransactionError::Invalid(
                        "observer canonical abort requires non-zero epoch and height".into(),
                    ));
                }
                if let Some(existing_abort) = Self::load_asymptote_observer_canonical_abort(
                    state,
                    abort.epoch,
                    abort.height,
                    abort.view,
                )? {
                    if existing_abort != abort {
                        return Err(TransactionError::Invalid(
                            "conflicting observer canonical abort already published for slot"
                                .into(),
                        ));
                    }
                    return Ok(());
                }
                Self::materialize_observer_abort(state, abort)?;
                Ok(())
            }
            "register_effect_proof_verifier@v1" => {
                let verifier: EffectProofVerifierDescriptor = codec::from_bytes_canonical(params)?;
                if verifier.verifier_id.trim().is_empty() {
                    return Err(TransactionError::Invalid(
                        "effect proof verifier id must not be empty".into(),
                    ));
                }
                state.insert(
                    &guardian_registry_effect_verifier_key(&verifier.verifier_id),
                    &codec::to_bytes_canonical(&verifier)
                        .map_err(TransactionError::Serialization)?,
                )?;
                Ok(())
            }
            "record_sealed_effect@v1" => {
                let record: SealedEffectRecord = codec::from_bytes_canonical(params)?;
                if record.nullifier == [0u8; 32] {
                    return Err(TransactionError::Invalid(
                        "sealed effect nullifier must be non-zero".into(),
                    ));
                }
                if record.intent_hash == [0u8; 32] {
                    return Err(TransactionError::Invalid(
                        "sealed effect intent hash must be non-zero".into(),
                    ));
                }
                if record.verifier_id.trim().is_empty() {
                    return Err(TransactionError::Invalid(
                        "sealed effect verifier id must not be empty".into(),
                    ));
                }
                let bytes =
                    codec::to_bytes_canonical(&record).map_err(TransactionError::Serialization)?;
                state.insert(
                    &guardian_registry_effect_nullifier_key(&record.nullifier),
                    &bytes,
                )?;
                state.insert(
                    &guardian_registry_sealed_effect_key(&record.intent_hash),
                    &bytes,
                )?;
                Ok(())
            }
            "publish_aft_bulletin_commitment@v1" => {
                let bulletin: BulletinCommitment = codec::from_bytes_canonical(params)?;
                if bulletin.height == 0 {
                    return Err(TransactionError::Invalid(
                        "aft bulletin commitment height must be non-zero".into(),
                    ));
                }
                if bulletin.bulletin_root == [0u8; 32] {
                    return Err(TransactionError::Invalid(
                        "aft bulletin commitment root must be non-zero".into(),
                    ));
                }
                state.insert(
                    &aft_bulletin_commitment_key(bulletin.height),
                    &codec::to_bytes_canonical(&bulletin)
                        .map_err(TransactionError::Serialization)?,
                )?;
                Ok(())
            }
            "publish_aft_bulletin_entry@v1" => {
                let entry: BulletinSurfaceEntry = codec::from_bytes_canonical(params)?;
                if entry.height == 0 || entry.tx_hash == [0u8; 32] {
                    return Err(TransactionError::Invalid(
                        "aft bulletin entry requires non-zero height and tx hash".into(),
                    ));
                }
                state.insert(
                    &aft_bulletin_entry_key(entry.height, &entry.tx_hash),
                    &codec::to_bytes_canonical(&entry).map_err(TransactionError::Serialization)?,
                )?;
                Ok(())
            }
            "publish_aft_bulletin_availability_certificate@v1" => {
                let certificate: BulletinAvailabilityCertificate =
                    codec::from_bytes_canonical(params)?;
                if certificate.height == 0
                    || certificate.bulletin_commitment_hash == [0u8; 32]
                    || certificate.recoverability_root == [0u8; 32]
                {
                    return Err(TransactionError::Invalid(
                        "aft bulletin availability certificate requires non-zero height and roots"
                            .into(),
                    ));
                }
                state.insert(
                    &aft_bulletin_availability_certificate_key(certificate.height),
                    &codec::to_bytes_canonical(&certificate)
                        .map_err(TransactionError::Serialization)?,
                )?;
                Ok(())
            }
            "publish_aft_publication_frontier@v1" => {
                let frontier: PublicationFrontier = codec::from_bytes_canonical(params)?;
                if frontier.height == 0
                    || frontier.counter == 0
                    || frontier.bulletin_commitment_hash == [0u8; 32]
                    || frontier.ordered_transactions_root_hash == [0u8; 32]
                    || frontier.availability_receipt_hash == [0u8; 32]
                {
                    return Err(TransactionError::Invalid(
                        "aft publication frontier requires non-zero height, counter, and compact commitments"
                            .into(),
                    ));
                }
                if Self::load_publication_frontier_contradiction(state, frontier.height)?.is_some()
                {
                    return Err(TransactionError::Invalid(
                        "cannot publish a positive publication frontier after a contradiction already dominates the slot"
                            .into(),
                    ));
                }
                if let Some(existing_abort) =
                    Self::load_canonical_order_abort(state, frontier.height)?
                {
                    return Err(TransactionError::Invalid(format!(
                        "cannot publish a positive publication frontier after canonical-order abort publication: {}",
                        existing_abort.details
                    )));
                }
                if let Some(existing) = Self::load_publication_frontier(state, frontier.height)? {
                    if existing != frontier {
                        Self::materialize_publication_frontier_contradiction(
                            state,
                            PublicationFrontierContradiction {
                                height: frontier.height,
                                kind: PublicationFrontierContradictionKind::ConflictingFrontier,
                                candidate_frontier: frontier,
                                reference_frontier: existing,
                            },
                        )?;
                    }
                    return Ok(());
                }
                if frontier.height > 1 {
                    if let Some(previous) =
                        Self::load_publication_frontier(state, frontier.height - 1)?
                    {
                        let expected_parent_hash = canonical_publication_frontier_hash(&previous)
                            .map_err(TransactionError::Invalid)?;
                        if frontier.counter != previous.counter.saturating_add(1)
                            || frontier.parent_frontier_hash != expected_parent_hash
                        {
                            Self::materialize_publication_frontier_contradiction(
                                state,
                                PublicationFrontierContradiction {
                                    height: frontier.height,
                                    kind: PublicationFrontierContradictionKind::StaleParentLink,
                                    candidate_frontier: frontier,
                                    reference_frontier: previous,
                                },
                            )?;
                            return Ok(());
                        }
                    }
                }
                state.insert(
                    &aft_publication_frontier_key(frontier.height),
                    &codec::to_bytes_canonical(&frontier)
                        .map_err(TransactionError::Serialization)?,
                )?;
                Ok(())
            }
            "publish_aft_recovery_capsule@v1" => {
                let capsule: RecoveryCapsule = codec::from_bytes_canonical(params)?;
                if capsule.height == 0
                    || capsule.coding.recovery_threshold == 0
                    || capsule.recovery_committee_root_hash == [0u8; 32]
                    || capsule.payload_commitment_hash == [0u8; 32]
                    || capsule.coding_root_hash == [0u8; 32]
                    || capsule.recovery_window_close_ms == 0
                {
                    return Err(TransactionError::Invalid(
                        "aft recovery capsule requires non-zero height, threshold, roots, and recovery window"
                            .into(),
                    ));
                }
                if let Some(existing) = Self::load_recovery_capsule(state, capsule.height)? {
                    if existing != capsule {
                        return Err(TransactionError::Invalid(
                            "conflicting aft recovery capsule already published for height".into(),
                        ));
                    }
                    return Ok(());
                }
                state.insert(
                    &aft_recovery_capsule_key(capsule.height),
                    &codec::to_bytes_canonical(&capsule)
                        .map_err(TransactionError::Serialization)?,
                )?;
                Ok(())
            }
            "publish_aft_recovery_witness_certificate@v1" => {
                let certificate: RecoveryWitnessCertificate = codec::from_bytes_canonical(params)?;
                if certificate.height == 0
                    || certificate.witness_manifest_hash == [0u8; 32]
                    || certificate.recovery_capsule_hash == [0u8; 32]
                    || certificate.share_commitment_hash == [0u8; 32]
                {
                    return Err(TransactionError::Invalid(
                        "aft recovery witness certificate requires non-zero height, witness manifest, capsule, and share commitment"
                            .into(),
                    ));
                }
                let capsule =
                    Self::load_recovery_capsule(state, certificate.height)?.ok_or_else(|| {
                        TransactionError::Invalid(
                            "aft recovery witness certificate requires a published recovery capsule"
                                .into(),
                        )
                    })?;
                let expected_capsule_hash =
                    canonical_recovery_capsule_hash(&capsule).map_err(TransactionError::Invalid)?;
                if certificate.recovery_capsule_hash != expected_capsule_hash {
                    return Err(TransactionError::Invalid(
                        "aft recovery witness certificate must bind the published recovery capsule"
                            .into(),
                    ));
                }
                let key = aft_recovery_witness_certificate_key(
                    certificate.height,
                    &certificate.witness_manifest_hash,
                );
                if let Some(existing) = Self::load_recovery_witness_certificate(
                    state,
                    certificate.height,
                    &certificate.witness_manifest_hash,
                )? {
                    if existing != certificate {
                        return Err(TransactionError::Invalid(
                            "conflicting aft recovery witness certificate already published for witness manifest"
                                .into(),
                        ));
                    }
                    return Ok(());
                }
                state.insert(
                    &key,
                    &codec::to_bytes_canonical(&certificate)
                        .map_err(TransactionError::Serialization)?,
                )?;
                Ok(())
            }
            "publish_aft_recovery_share_receipt@v1" => {
                let receipt: RecoveryShareReceipt = codec::from_bytes_canonical(params)?;
                if receipt.height == 0
                    || receipt.witness_manifest_hash == [0u8; 32]
                    || receipt.block_commitment_hash == [0u8; 32]
                    || receipt.share_commitment_hash == [0u8; 32]
                {
                    return Err(TransactionError::Invalid(
                        "aft recovery share receipt requires non-zero height, witness manifest, block commitment, and share commitment"
                            .into(),
                    ));
                }
                let certificate = Self::load_recovery_witness_certificate(
                    state,
                    receipt.height,
                    &receipt.witness_manifest_hash,
                )?
                .ok_or_else(|| {
                    TransactionError::Invalid(
                        "aft recovery share receipt requires a published recovery witness certificate"
                            .into(),
                    )
                })?;
                if certificate.share_commitment_hash != receipt.share_commitment_hash {
                    return Err(TransactionError::Invalid(
                        "aft recovery share receipt must match the witness certificate share commitment"
                            .into(),
                    ));
                }
                if certificate.witness_manifest_hash != receipt.witness_manifest_hash {
                    return Err(TransactionError::Invalid(
                        "aft recovery share receipt must bind the witness manifest carried by the witness certificate"
                            .into(),
                    ));
                }
                if Self::load_missing_recovery_share(
                    state,
                    receipt.height,
                    &receipt.witness_manifest_hash,
                )?
                .is_some()
                {
                    return Err(TransactionError::Invalid(
                        "cannot publish an aft recovery share receipt after missing-share publication"
                            .into(),
                    ));
                }
                let key = aft_recovery_share_receipt_key(
                    receipt.height,
                    &receipt.witness_manifest_hash,
                    &receipt.block_commitment_hash,
                );
                if let Some(existing) = state.get(&key)? {
                    let existing: RecoveryShareReceipt = codec::from_bytes_canonical(&existing)
                        .map_err(|e| TransactionError::Invalid(e.to_string()))?;
                    if existing != receipt {
                        return Err(TransactionError::Invalid(
                            "conflicting aft recovery share receipt already published for witness and block"
                                .into(),
                        ));
                    }
                    return Ok(());
                }
                state.insert(
                    &key,
                    &codec::to_bytes_canonical(&receipt)
                        .map_err(TransactionError::Serialization)?,
                )?;
                Self::materialize_recovery_impossible_abort_if_needed(state, receipt.height)?;
                Ok(())
            }
            "publish_aft_recovery_share_material@v1" => {
                let material: RecoveryShareMaterial = codec::from_bytes_canonical(params)?;
                if material.height == 0
                    || material.witness_manifest_hash == [0u8; 32]
                    || material.block_commitment_hash == [0u8; 32]
                    || material.share_commitment_hash == [0u8; 32]
                {
                    return Err(TransactionError::Invalid(
                        "aft recovery share material requires non-zero height, witness manifest, block commitment, and share commitment"
                            .into(),
                    ));
                }
                let certificate = Self::load_recovery_witness_certificate(
                    state,
                    material.height,
                    &material.witness_manifest_hash,
                )?
                .ok_or_else(|| {
                    TransactionError::Invalid(
                        "aft recovery share material requires a published recovery witness certificate"
                            .into(),
                    )
                })?;
                if certificate.share_commitment_hash != material.share_commitment_hash {
                    return Err(TransactionError::Invalid(
                        "aft recovery share material must match the witness certificate share commitment"
                            .into(),
                    ));
                }
                if certificate.witness_manifest_hash != material.witness_manifest_hash {
                    return Err(TransactionError::Invalid(
                        "aft recovery share material must bind the witness manifest carried by the witness certificate"
                            .into(),
                    ));
                }
                if Self::load_missing_recovery_share(
                    state,
                    material.height,
                    &material.witness_manifest_hash,
                )?
                .is_some()
                {
                    return Err(TransactionError::Invalid(
                        "cannot publish aft recovery share material after missing-share publication"
                            .into(),
                    ));
                }
                let expected_receipt = material.to_recovery_share_receipt();
                let receipt_key = aft_recovery_share_receipt_key(
                    material.height,
                    &material.witness_manifest_hash,
                    &material.block_commitment_hash,
                );
                let receipt_bytes = state.get(&receipt_key)?.ok_or_else(|| {
                    TransactionError::Invalid(
                        "aft recovery share material requires a published matching recovery share receipt"
                            .into(),
                    )
                })?;
                let receipt: RecoveryShareReceipt = codec::from_bytes_canonical(&receipt_bytes)
                    .map_err(|e| TransactionError::Invalid(e.to_string()))?;
                if receipt != expected_receipt {
                    return Err(TransactionError::Invalid(
                        "aft recovery share material must match the published recovery share receipt"
                            .into(),
                    ));
                }
                let key = aft_recovery_share_material_key(
                    material.height,
                    &material.witness_manifest_hash,
                    &material.block_commitment_hash,
                );
                if let Some(existing) = state.get(&key)? {
                    let existing: RecoveryShareMaterial = codec::from_bytes_canonical(&existing)
                        .map_err(|e| TransactionError::Invalid(e.to_string()))?;
                    if existing != material {
                        return Err(TransactionError::Invalid(
                            "conflicting aft recovery share material already published for witness and block"
                                .into(),
                        ));
                    }
                    return Ok(());
                }
                state.insert(
                    &key,
                    &codec::to_bytes_canonical(&material)
                        .map_err(TransactionError::Serialization)?,
                )?;
                Ok(())
            }
            "publish_aft_recovered_publication_bundle@v1" => {
                let recovered: RecoveredPublicationBundle = codec::from_bytes_canonical(params)?;
                if recovered.height == 0
                    || recovered.block_commitment_hash == [0u8; 32]
                    || recovered.coding.recovery_threshold == 0
                    || recovered.recoverable_slot_payload_hash == [0u8; 32]
                    || recovered.recoverable_full_surface_hash == [0u8; 32]
                    || recovered.canonical_order_publication_bundle_hash == [0u8; 32]
                    || recovered.canonical_bulletin_close_hash == [0u8; 32]
                {
                    return Err(TransactionError::Invalid(
                        "aft recovered publication bundle requires non-zero height, block commitment, threshold, v4 hash, v5 hash, publication-bundle hash, and bulletin-close hash"
                            .into(),
                    ));
                }
                let normalized_witnesses =
                    normalize_recovered_publication_bundle_supporting_witnesses(
                        &recovered.supporting_witness_manifest_hashes,
                    )
                    .map_err(TransactionError::Invalid)?;
                if normalized_witnesses != recovered.supporting_witness_manifest_hashes {
                    return Err(TransactionError::Invalid(
                        "aft recovered publication bundle must carry canonical sorted supporting witness manifests"
                            .into(),
                    ));
                }
                if normalized_witnesses.len() != usize::from(recovered.coding.recovery_threshold) {
                    return Err(TransactionError::Invalid(
                        "aft recovered publication bundle supporting witness count must match the recovery threshold"
                            .into(),
                    ));
                }

                let materials =
                    Self::load_supporting_recovery_share_materials_for_recovered_bundle(
                        state, &recovered,
                    )
                    .map_err(|error| TransactionError::Invalid(error.to_string()))?;
                let (_, full_surface, bundle, bulletin_close) =
                    Self::reconstruct_recovered_publication_surface(&recovered, &materials)
                        .map_err(|error| TransactionError::Invalid(error.to_string()))?;

                let key = aft_recovered_publication_bundle_key(
                    recovered.height,
                    &recovered.block_commitment_hash,
                    &recovered.supporting_witness_manifest_hashes,
                )
                .map_err(TransactionError::Invalid)?;
                let recovered_bytes = codec::to_bytes_canonical(&recovered)
                    .map_err(TransactionError::Serialization)?;
                let conflicting_existing =
                    Self::load_recovered_publication_bundles_for_height(state, recovered.height)?
                        .into_iter()
                        .find(|existing| {
                            Self::recovered_publication_bundle_conflicts(existing, &recovered)
                        });
                if let Some(existing) = state.get(&key)? {
                    let existing: RecoveredPublicationBundle =
                        codec::from_bytes_canonical(&existing)
                            .map_err(|e| TransactionError::Invalid(e.to_string()))?;
                    if existing != recovered {
                        return Err(TransactionError::Invalid(
                            "conflicting aft recovered publication bundle already published for the same support set"
                                .into(),
                        ));
                    }
                    if conflicting_existing.is_none() {
                        return Ok(());
                    }
                } else {
                    state.insert(&key, &recovered_bytes)?;
                }
                if let Some(existing) = conflicting_existing {
                    let abort = Self::build_canonical_order_abort(
                        recovered.height,
                        CanonicalOrderAbortReason::RecoverySupportConflict,
                        format!(
                            "published recovered publication bundle conflicts with an existing recovered slot surface for height {}",
                            existing.height
                        ),
                        None,
                        None,
                    );
                    Self::materialize_canonical_order_abort(state, abort)?;
                    return Ok(());
                }
                self.materialize_canonical_order_publication_bundle(
                    state,
                    &bundle,
                    &bulletin_close,
                    ctx,
                )?;
                let previous_collapse = if full_surface.height <= 1 {
                    None
                } else {
                    Self::load_canonical_collapse_object(state, full_surface.height - 1)?
                };
                let recovered_collapse = derive_canonical_collapse_object_from_recovered_surface(
                    &full_surface,
                    &bulletin_close,
                    previous_collapse.as_ref(),
                )
                .map_err(TransactionError::Invalid)?;
                let mut recovered_collapse = recovered_collapse;
                if let Some((checkpoint_hash, activation_hash, receipt_hash)) =
                    Self::load_latest_canonical_archived_history_anchor_hashes(state)?
                {
                    set_canonical_collapse_archived_recovered_history_anchor(
                        &mut recovered_collapse,
                        checkpoint_hash,
                        activation_hash,
                        receipt_hash,
                    )
                    .map_err(TransactionError::Invalid)?;
                }
                Self::materialize_canonical_collapse_object(state, recovered_collapse)?;
                state.insert(&key, &recovered_bytes)?;
                Ok(())
            }
            "publish_aft_archived_recovered_history_segment@v1" => {
                let segment: ArchivedRecoveredHistorySegment = codec::from_bytes_canonical(params)?;
                let segment_hash = canonical_archived_recovered_history_segment_hash(&segment)
                    .map_err(TransactionError::Invalid)?;
                if segment.start_height == 0
                    || segment.end_height == 0
                    || segment.end_height < segment.start_height
                    || segment.archived_profile_hash == [0u8; 32]
                    || segment.archived_profile_activation_hash == [0u8; 32]
                    || segment.first_recovered_publication_bundle_hash == [0u8; 32]
                    || segment.last_recovered_publication_bundle_hash == [0u8; 32]
                    || segment.segment_root_hash == [0u8; 32]
                {
                    return Err(TransactionError::Invalid(
                        "aft archived recovered-history segment requires a valid height range, non-zero archived profile hash, non-zero archived profile activation hash, first/last recovered bundle hashes, and segment root"
                            .into(),
                    ));
                }
                let profile = Self::load_archived_recovered_history_profile_by_hash(
                    state,
                    &segment.archived_profile_hash,
                )?
                .ok_or_else(|| {
                    TransactionError::Invalid(
                        "aft archived recovered-history segment requires its archived profile to be published first"
                            .into(),
                    )
                })?;
                validate_archived_recovered_history_segment_against_profile(&segment, &profile)
                    .map_err(TransactionError::Invalid)?;
                Self::validate_archived_recovered_history_profile_activation_for_tip_height_by_hash(
                    state,
                    &segment.archived_profile_activation_hash,
                    &segment.archived_profile_hash,
                    segment.end_height,
                )
                .map_err(|error| TransactionError::Invalid(error.to_string()))?;
                if (segment.overlap_start_height == 0) != (segment.overlap_end_height == 0) {
                    return Err(TransactionError::Invalid(
                        "aft archived recovered-history segment overlap heights must both be zero or both be non-zero"
                            .into(),
                    ));
                }
                if segment.overlap_start_height == 0 {
                    if segment.overlap_root_hash != [0u8; 32] {
                        return Err(TransactionError::Invalid(
                            "aft archived recovered-history segment without an overlap range must use the zero overlap root"
                                .into(),
                        ));
                    }
                } else if segment.overlap_end_height < segment.overlap_start_height
                    || segment.overlap_start_height < segment.start_height
                    || segment.overlap_end_height > segment.end_height
                    || segment.overlap_root_hash == [0u8; 32]
                {
                    return Err(TransactionError::Invalid(
                        "aft archived recovered-history segment overlap range must lie within the covered range and carry a non-zero overlap root"
                            .into(),
                    ));
                }
                let key = aft_archived_recovered_history_segment_key(
                    segment.start_height,
                    segment.end_height,
                );
                let hash_key = aft_archived_recovered_history_segment_hash_key(&segment_hash);
                let segment_bytes =
                    codec::to_bytes_canonical(&segment).map_err(TransactionError::Serialization)?;

                if let Some(existing) = state.get(&hash_key)? {
                    let existing: ArchivedRecoveredHistorySegment =
                        codec::from_bytes_canonical(&existing)
                            .map_err(|e| TransactionError::Invalid(e.to_string()))?;
                    if existing != segment {
                        return Err(TransactionError::Invalid(
                            "conflicting aft archived recovered-history segment already published for the same segment hash"
                                .into(),
                        ));
                    }
                }

                if let Some(existing) = state.get(&key)? {
                    let existing: ArchivedRecoveredHistorySegment =
                        codec::from_bytes_canonical(&existing)
                            .map_err(|e| TransactionError::Invalid(e.to_string()))?;
                    if existing != segment {
                        return Err(TransactionError::Invalid(
                            "conflicting aft archived recovered-history segment already published for the same covered range"
                                .into(),
                        ));
                    }
                    if state.get(&hash_key)?.is_none() {
                        state.insert(&hash_key, &segment_bytes)?;
                    }
                    return Ok(());
                }
                state.insert(&key, &segment_bytes)?;
                state.insert(&hash_key, &segment_bytes)?;
                Ok(())
            }
            "publish_aft_archived_recovered_history_profile@v1" => {
                let profile: ArchivedRecoveredHistoryProfile = codec::from_bytes_canonical(params)?;
                let expected = build_archived_recovered_history_profile(
                    profile.retention_horizon,
                    profile.restart_page_window,
                    profile.restart_page_overlap,
                    profile.windows_per_segment,
                    profile.segments_per_fold,
                    profile.checkpoint_update_rule,
                )
                .map_err(TransactionError::Invalid)?;
                if expected != profile {
                    return Err(TransactionError::Invalid(
                        "aft archived recovered-history profile is not canonically normalized"
                            .into(),
                    ));
                }
                validate_archived_recovered_history_profile(&profile)
                    .map_err(TransactionError::Invalid)?;
                let profile_hash = canonical_archived_recovered_history_profile_hash(&profile)
                    .map_err(TransactionError::Invalid)?;
                let profile_bytes =
                    codec::to_bytes_canonical(&profile).map_err(TransactionError::Serialization)?;
                let hash_key = aft_archived_recovered_history_profile_hash_key(&profile_hash);

                if let Some(existing) = state.get(&hash_key)? {
                    let existing: ArchivedRecoveredHistoryProfile =
                        codec::from_bytes_canonical(&existing)
                            .map_err(|e| TransactionError::Invalid(e.to_string()))?;
                    if existing != profile {
                        return Err(TransactionError::Invalid(
                            "conflicting aft archived recovered-history profile already published for the same profile hash"
                                .into(),
                        ));
                    }
                } else {
                    state.insert(&hash_key, &profile_bytes)?;
                }
                Ok(())
            }
            "publish_aft_archived_recovered_history_profile_activation@v1" => {
                let activation: ArchivedRecoveredHistoryProfileActivation =
                    codec::from_bytes_canonical(params)?;
                if activation.archived_profile_hash == [0u8; 32]
                    || activation.activation_end_height == 0
                {
                    return Err(TransactionError::Invalid(
                        "aft archived recovered-history profile activation requires a non-zero profile hash and activation end height"
                            .into(),
                    ));
                }
                let profile = Self::load_archived_recovered_history_profile_by_hash(
                    state,
                    &activation.archived_profile_hash,
                )?
                .ok_or_else(|| {
                    TransactionError::Invalid(
                        "aft archived recovered-history profile activation requires the referenced archived profile to be published first"
                            .into(),
                    )
                })?;
                validate_archived_recovered_history_profile_activation(&activation, &profile)
                    .map_err(TransactionError::Invalid)?;

                let existing_by_profile = Self::load_archived_recovered_history_profile_activation(
                    state,
                    &activation.archived_profile_hash,
                )?;
                if let Some(existing) = existing_by_profile.as_ref() {
                    if existing != &activation {
                        return Err(TransactionError::Invalid(
                            "conflicting aft archived recovered-history profile activation already published for the same profile hash"
                                .into(),
                        ));
                    }
                }

                let existing_by_height =
                    Self::load_archived_recovered_history_profile_activation_for_end_height(
                        state,
                        activation.activation_end_height,
                    )?;
                if let Some(existing) = existing_by_height.as_ref() {
                    if existing != &activation {
                        return Err(TransactionError::Invalid(
                            "conflicting aft archived recovered-history profile activation already published for the same activation end height"
                                .into(),
                        ));
                    }
                }

                let activation_checkpoint = if activation.activation_checkpoint_hash == [0u8; 32] {
                    None
                } else {
                    let checkpoint =
                        Self::load_archived_recovered_history_checkpoint_by_hash(
                            state,
                            &activation.activation_checkpoint_hash,
                        )?
                        .ok_or_else(|| {
                            TransactionError::Invalid(
                                "aft archived recovered-history profile activation requires its activation checkpoint to be published first"
                                    .into(),
                            )
                        })?;
                    if checkpoint.archived_profile_hash != activation.archived_profile_hash {
                        return Err(TransactionError::Invalid(
                            "aft archived recovered-history profile activation checkpoint profile hash does not match the activated profile"
                                .into(),
                        ));
                    }
                    if checkpoint.covered_end_height != activation.activation_end_height {
                        return Err(TransactionError::Invalid(
                            "aft archived recovered-history profile activation checkpoint tip does not match the declared activation end height"
                                .into(),
                        ));
                    }
                    Some(checkpoint)
                };

                let latest_activation =
                    Self::load_latest_archived_recovered_history_profile_activation(state)?;
                if existing_by_profile.is_none() && existing_by_height.is_none() {
                    if let Some(previous_activation) = latest_activation.as_ref() {
                        validate_archived_recovered_history_profile_activation_successor(
                            previous_activation,
                            &activation,
                        )
                        .map_err(TransactionError::Invalid)?;
                    } else if activation.previous_archived_profile_hash != [0u8; 32] {
                        return Err(TransactionError::Invalid(
                            "bootstrap aft archived recovered-history profile activation must use the zero previous profile hash"
                                .into(),
                        ));
                    }
                    let expected = build_archived_recovered_history_profile_activation(
                        &profile,
                        latest_activation.as_ref(),
                        activation.activation_end_height,
                        activation_checkpoint.as_ref(),
                    )
                    .map_err(TransactionError::Invalid)?;
                    if expected != activation {
                        return Err(TransactionError::Invalid(
                            "aft archived recovered-history profile activation is not canonically normalized"
                                .into(),
                        ));
                    }
                }

                let activation_key = aft_archived_recovered_history_profile_activation_key(
                    &activation.archived_profile_hash,
                );
                let height_key = aft_archived_recovered_history_profile_activation_height_key(
                    activation.activation_end_height,
                );
                let activation_hash =
                    canonical_archived_recovered_history_profile_activation_hash(&activation)
                        .map_err(TransactionError::Invalid)?;
                let hash_key =
                    aft_archived_recovered_history_profile_activation_hash_key(&activation_hash);
                let activation_bytes = codec::to_bytes_canonical(&activation)
                    .map_err(TransactionError::Serialization)?;
                if state.get(&activation_key)?.is_none() {
                    state.insert(&activation_key, &activation_bytes)?;
                }
                if state.get(&height_key)?.is_none() {
                    state.insert(&height_key, &activation_bytes)?;
                }
                if state.get(&hash_key)?.is_none() {
                    state.insert(&hash_key, &activation_bytes)?;
                }

                match latest_activation {
                    Some(existing_latest) if existing_latest == activation => {}
                    Some(_existing_latest) if existing_by_profile.is_some() => {}
                    Some(existing_latest) => {
                        if activation.activation_end_height <= existing_latest.activation_end_height
                        {
                            return Err(TransactionError::Invalid(
                                "aft archived recovered-history profile activation must advance beyond the current latest activation tip"
                                    .into(),
                            ));
                        }
                        state.insert(
                            AFT_LATEST_ARCHIVED_RECOVERED_HISTORY_PROFILE_ACTIVATION_KEY,
                            &activation_bytes,
                        )?;
                    }
                    None => {
                        state.insert(
                            AFT_LATEST_ARCHIVED_RECOVERED_HISTORY_PROFILE_ACTIVATION_KEY,
                            &activation_bytes,
                        )?;
                    }
                }

                let profile_bytes =
                    codec::to_bytes_canonical(&profile).map_err(TransactionError::Serialization)?;
                state.insert(
                    AFT_ACTIVE_ARCHIVED_RECOVERED_HISTORY_PROFILE_KEY,
                    &profile_bytes,
                )?;
                Ok(())
            }
            "publish_aft_archived_recovered_restart_page@v1" => {
                let page: ArchivedRecoveredRestartPage = codec::from_bytes_canonical(params)?;
                if page.segment_hash == [0u8; 32]
                    || page.archived_profile_hash == [0u8; 32]
                    || page.archived_profile_activation_hash == [0u8; 32]
                    || page.start_height == 0
                    || page.end_height == 0
                    || page.end_height < page.start_height
                    || page.restart_headers.is_empty()
                {
                    return Err(TransactionError::Invalid(
                        "aft archived recovered restart page requires a non-zero segment hash, archived profile hash, archived profile activation hash, valid range, and at least one restart header"
                            .into(),
                    ));
                }
                if page.restart_headers[0].header.height != page.start_height
                    || page
                        .restart_headers
                        .last()
                        .map(|entry| entry.header.height)
                        .ok_or_else(|| {
                            TransactionError::Invalid(
                                "aft archived recovered restart page is missing its end height"
                                    .into(),
                            )
                        })?
                        != page.end_height
                {
                    return Err(TransactionError::Invalid(
                        "aft archived recovered restart page heights do not match the archived page range"
                            .into(),
                    ));
                }
                for pair in page.restart_headers.windows(2) {
                    if pair[1].header.height != pair[0].header.height + 1 {
                        return Err(TransactionError::Invalid(
                            "aft archived recovered restart page requires contiguous restart-header heights"
                                .into(),
                        ));
                    }
                }

                let Some(segment) = Self::load_archived_recovered_history_segment_by_hash(
                    state,
                    &page.segment_hash,
                )?
                else {
                    return Err(TransactionError::Invalid(
                        "aft archived recovered restart page requires the archived segment descriptor to be published first"
                            .into(),
                    ));
                };
                let profile = Self::load_archived_recovered_history_profile_by_hash(
                    state,
                    &page.archived_profile_hash,
                )?
                .ok_or_else(|| {
                    TransactionError::Invalid(
                        "aft archived recovered restart page requires its archived profile to be published first"
                            .into(),
                    )
                })?;
                if segment.archived_profile_hash != page.archived_profile_hash {
                    return Err(TransactionError::Invalid(
                        "aft archived recovered restart page profile hash does not match the archived segment descriptor"
                            .into(),
                    ));
                }
                if segment.archived_profile_activation_hash != page.archived_profile_activation_hash
                {
                    return Err(TransactionError::Invalid(
                        "aft archived recovered restart page activation hash does not match the archived segment descriptor"
                            .into(),
                    ));
                }
                validate_archived_recovered_restart_page_against_profile(&page, &profile)
                    .map_err(TransactionError::Invalid)?;
                Self::validate_archived_recovered_history_profile_activation_for_tip_height_by_hash(
                    state,
                    &page.archived_profile_activation_hash,
                    &page.archived_profile_hash,
                    page.end_height,
                )
                .map_err(|error| TransactionError::Invalid(error.to_string()))?;
                let expected_page =
                    build_archived_recovered_restart_page(&segment, &page.restart_headers)
                        .map_err(TransactionError::Invalid)?;
                if expected_page != page {
                    return Err(TransactionError::Invalid(
                        "aft archived recovered restart page does not match the archived segment range or segment hash"
                            .into(),
                    ));
                }

                let key = aft_archived_recovered_restart_page_key(&page.segment_hash);
                if let Some(existing) = state.get(&key)? {
                    let existing: ArchivedRecoveredRestartPage =
                        codec::from_bytes_canonical(&existing)
                            .map_err(|e| TransactionError::Invalid(e.to_string()))?;
                    if existing != page {
                        return Err(TransactionError::Invalid(
                            "conflicting aft archived recovered restart page already published for the same segment hash"
                                .into(),
                        ));
                    }
                    return Ok(());
                }
                state.insert(
                    &key,
                    &codec::to_bytes_canonical(&page).map_err(TransactionError::Serialization)?,
                )?;
                Ok(())
            }
            "publish_aft_archived_recovered_history_checkpoint@v1" => {
                let checkpoint: ArchivedRecoveredHistoryCheckpoint =
                    codec::from_bytes_canonical(params)?;
                if checkpoint.covered_start_height == 0
                    || checkpoint.covered_end_height == 0
                    || checkpoint.covered_end_height < checkpoint.covered_start_height
                    || checkpoint.archived_profile_hash == [0u8; 32]
                    || checkpoint.archived_profile_activation_hash == [0u8; 32]
                    || checkpoint.latest_archived_segment_hash == [0u8; 32]
                    || checkpoint.latest_archived_restart_page_hash == [0u8; 32]
                {
                    return Err(TransactionError::Invalid(
                        "aft archived recovered-history checkpoint requires a valid covered range, non-zero archived profile hash, non-zero archived profile activation hash, and non-zero segment/page hashes"
                            .into(),
                    ));
                }
                let profile = Self::load_archived_recovered_history_profile_by_hash(
                    state,
                    &checkpoint.archived_profile_hash,
                )?
                .ok_or_else(|| {
                    TransactionError::Invalid(
                        "aft archived recovered-history checkpoint requires its archived profile to be published first"
                            .into(),
                    )
                })?;
                validate_archived_recovered_history_checkpoint_against_profile(
                    &checkpoint,
                    &profile,
                )
                .map_err(TransactionError::Invalid)?;
                Self::validate_archived_recovered_history_profile_activation_for_tip_height_by_hash(
                    state,
                    &checkpoint.archived_profile_activation_hash,
                    &checkpoint.archived_profile_hash,
                    checkpoint.covered_end_height,
                )
                .map_err(|error| TransactionError::Invalid(error.to_string()))?;

                let Some(segment) = Self::load_archived_recovered_history_segment_by_hash(
                    state,
                    &checkpoint.latest_archived_segment_hash,
                )?
                else {
                    return Err(TransactionError::Invalid(
                        "aft archived recovered-history checkpoint requires the archived segment descriptor to be published first"
                            .into(),
                    ));
                };
                if segment.start_height != checkpoint.covered_start_height
                    || segment.end_height != checkpoint.covered_end_height
                {
                    return Err(TransactionError::Invalid(
                        "aft archived recovered-history checkpoint covered range does not match the archived segment descriptor"
                            .into(),
                    ));
                }
                if segment.archived_profile_hash != checkpoint.archived_profile_hash {
                    return Err(TransactionError::Invalid(
                        "aft archived recovered-history checkpoint profile hash does not match the archived segment descriptor"
                            .into(),
                    ));
                }
                if segment.archived_profile_activation_hash
                    != checkpoint.archived_profile_activation_hash
                {
                    return Err(TransactionError::Invalid(
                        "aft archived recovered-history checkpoint activation hash does not match the archived segment descriptor"
                            .into(),
                    ));
                }

                let Some(page) = Self::load_archived_recovered_restart_page(
                    state,
                    &checkpoint.latest_archived_segment_hash,
                )?
                else {
                    return Err(TransactionError::Invalid(
                        "aft archived recovered-history checkpoint requires the archived restart page to be published first"
                            .into(),
                    ));
                };
                if page.start_height != checkpoint.covered_start_height
                    || page.end_height != checkpoint.covered_end_height
                {
                    return Err(TransactionError::Invalid(
                        "aft archived recovered-history checkpoint covered range does not match the archived restart page"
                            .into(),
                    ));
                }
                if page.archived_profile_hash != checkpoint.archived_profile_hash {
                    return Err(TransactionError::Invalid(
                        "aft archived recovered-history checkpoint profile hash does not match the archived restart page"
                            .into(),
                    ));
                }
                if page.archived_profile_activation_hash
                    != checkpoint.archived_profile_activation_hash
                {
                    return Err(TransactionError::Invalid(
                        "aft archived recovered-history checkpoint activation hash does not match the archived restart page"
                            .into(),
                    ));
                }
                let page_hash = canonical_archived_recovered_restart_page_hash(&page)
                    .map_err(TransactionError::Invalid)?;
                if page_hash != checkpoint.latest_archived_restart_page_hash {
                    return Err(TransactionError::Invalid(
                        "aft archived recovered-history checkpoint page hash does not match the archived restart page"
                            .into(),
                    ));
                }

                let previous_checkpoint = if checkpoint.previous_archived_checkpoint_hash
                    == [0u8; 32]
                {
                    None
                } else {
                    Some(
                        Self::load_archived_recovered_history_checkpoint_by_hash(
                            state,
                            &checkpoint.previous_archived_checkpoint_hash,
                        )?
                        .ok_or_else(|| {
                            TransactionError::Invalid(
                                "aft archived recovered-history checkpoint predecessor is missing from state"
                                    .into(),
                            )
                        })?,
                    )
                };
                let expected = build_archived_recovered_history_checkpoint(
                    &segment,
                    &page,
                    previous_checkpoint.as_ref(),
                )
                .map_err(TransactionError::Invalid)?;
                if expected != checkpoint {
                    return Err(TransactionError::Invalid(
                        "aft archived recovered-history checkpoint does not match the archived tip segment/page surface"
                            .into(),
                    ));
                }

                let checkpoint_hash =
                    canonical_archived_recovered_history_checkpoint_hash(&checkpoint)
                        .map_err(TransactionError::Invalid)?;
                let key = aft_archived_recovered_history_checkpoint_key(
                    checkpoint.covered_start_height,
                    checkpoint.covered_end_height,
                );
                let hash_key = aft_archived_recovered_history_checkpoint_hash_key(&checkpoint_hash);
                let checkpoint_bytes = codec::to_bytes_canonical(&checkpoint)
                    .map_err(TransactionError::Serialization)?;

                if let Some(existing) = state.get(&hash_key)? {
                    let existing: ArchivedRecoveredHistoryCheckpoint =
                        codec::from_bytes_canonical(&existing)
                            .map_err(|e| TransactionError::Invalid(e.to_string()))?;
                    if existing != checkpoint {
                        return Err(TransactionError::Invalid(
                            "conflicting aft archived recovered-history checkpoint already published for the same checkpoint hash"
                                .into(),
                        ));
                    }
                }

                if let Some(existing) = state.get(&key)? {
                    let existing: ArchivedRecoveredHistoryCheckpoint =
                        codec::from_bytes_canonical(&existing)
                            .map_err(|e| TransactionError::Invalid(e.to_string()))?;
                    if existing != checkpoint {
                        return Err(TransactionError::Invalid(
                            "conflicting aft archived recovered-history checkpoint already published for the same covered range"
                                .into(),
                        ));
                    }
                } else {
                    state.insert(&key, &checkpoint_bytes)?;
                }
                if state.get(&hash_key)?.is_none() {
                    state.insert(&hash_key, &checkpoint_bytes)?;
                }

                if let Some(existing_latest_bytes) =
                    state.get(AFT_LATEST_ARCHIVED_RECOVERED_HISTORY_CHECKPOINT_KEY)?
                {
                    let existing_latest: ArchivedRecoveredHistoryCheckpoint =
                        codec::from_bytes_canonical(&existing_latest_bytes)
                            .map_err(|e| TransactionError::Invalid(e.to_string()))?;
                    if existing_latest == checkpoint {
                        return Ok(());
                    }
                    if existing_latest.covered_end_height == checkpoint.covered_end_height {
                        return Err(TransactionError::Invalid(
                            "conflicting aft archived recovered-history checkpoint already published for the same latest tip height"
                                .into(),
                        ));
                    }
                    if checkpoint.covered_end_height > existing_latest.covered_end_height {
                        let existing_latest_hash =
                            canonical_archived_recovered_history_checkpoint_hash(&existing_latest)
                                .map_err(TransactionError::Invalid)?;
                        if checkpoint.previous_archived_checkpoint_hash != existing_latest_hash {
                            return Err(TransactionError::Invalid(
                                "aft archived recovered-history checkpoint advance must chain from the current latest checkpoint"
                                    .into(),
                            ));
                        }
                        state.insert(
                            AFT_LATEST_ARCHIVED_RECOVERED_HISTORY_CHECKPOINT_KEY,
                            &checkpoint_bytes,
                        )?;
                    }
                    return Ok(());
                }

                state.insert(
                    AFT_LATEST_ARCHIVED_RECOVERED_HISTORY_CHECKPOINT_KEY,
                    &checkpoint_bytes,
                )?;
                Ok(())
            }
            "publish_aft_archived_recovered_history_retention_receipt@v1" => {
                let receipt: ArchivedRecoveredHistoryRetentionReceipt =
                    codec::from_bytes_canonical(params)?;
                if receipt.covered_start_height == 0
                    || receipt.covered_end_height == 0
                    || receipt.covered_end_height < receipt.covered_start_height
                    || receipt.archived_profile_hash == [0u8; 32]
                    || receipt.archived_profile_activation_hash == [0u8; 32]
                    || receipt.archived_checkpoint_hash == [0u8; 32]
                    || receipt.validator_set_commitment_hash == [0u8; 32]
                {
                    return Err(TransactionError::Invalid(
                        "aft archived recovered-history retention receipt requires a valid covered range, archived profile hash, archived profile activation hash, checkpoint hash, and validator-set commitment hash"
                            .into(),
                    ));
                }

                let checkpoint = Self::load_archived_recovered_history_checkpoint_by_hash(
                    state,
                    &receipt.archived_checkpoint_hash,
                )?
                .ok_or_else(|| {
                    TransactionError::Invalid(
                        "aft archived recovered-history retention receipt requires the archived checkpoint to be published first"
                            .into(),
                    )
                })?;
                if checkpoint.covered_start_height != receipt.covered_start_height
                    || checkpoint.covered_end_height != receipt.covered_end_height
                {
                    return Err(TransactionError::Invalid(
                        "aft archived recovered-history retention receipt covered range does not match the archived checkpoint"
                            .into(),
                    ));
                }
                if checkpoint.archived_profile_hash != receipt.archived_profile_hash {
                    return Err(TransactionError::Invalid(
                        "aft archived recovered-history retention receipt profile hash does not match the archived checkpoint"
                            .into(),
                    ));
                }
                if checkpoint.archived_profile_activation_hash
                    != receipt.archived_profile_activation_hash
                {
                    return Err(TransactionError::Invalid(
                        "aft archived recovered-history retention receipt activation hash does not match the archived checkpoint"
                            .into(),
                    ));
                }
                let profile = Self::load_archived_recovered_history_profile_by_hash(
                    state,
                    &receipt.archived_profile_hash,
                )?
                .ok_or_else(|| {
                    TransactionError::Invalid(
                        "aft archived recovered-history retention receipt requires its archived profile to be published first"
                            .into(),
                    )
                })?;

                let Some(validator_set_bytes) = state.get(VALIDATOR_SET_KEY)? else {
                    return Err(TransactionError::Invalid(
                        "aft archived recovered-history retention receipt requires an active validator set"
                            .into(),
                    ));
                };
                let validator_sets = read_validator_sets(&validator_set_bytes)
                    .map_err(|error| TransactionError::Invalid(error.to_string()))?;
                let validator_set_commitment_hash = canonical_validator_sets_hash(&validator_sets)
                    .map_err(TransactionError::Invalid)?;
                let expected = build_archived_recovered_history_retention_receipt(
                    &checkpoint,
                    validator_set_commitment_hash,
                    receipt.retained_through_height,
                )
                .map_err(TransactionError::Invalid)?;
                validate_archived_recovered_history_retention_receipt_against_profile(
                    &receipt,
                    &checkpoint,
                    &profile,
                )
                .map_err(TransactionError::Invalid)?;
                Self::validate_archived_recovered_history_profile_activation_for_tip_height_by_hash(
                    state,
                    &receipt.archived_profile_activation_hash,
                    &receipt.archived_profile_hash,
                    receipt.covered_end_height,
                )
                .map_err(|error| TransactionError::Invalid(error.to_string()))?;
                if expected != receipt {
                    return Err(TransactionError::Invalid(
                        "aft archived recovered-history retention receipt does not match the archived checkpoint or current validator-set commitment"
                            .into(),
                    ));
                }

                let key = aft_archived_recovered_history_retention_receipt_key(
                    &receipt.archived_checkpoint_hash,
                );
                let receipt_bytes =
                    codec::to_bytes_canonical(&receipt).map_err(TransactionError::Serialization)?;
                if let Some(existing) = state.get(&key)? {
                    let existing: ArchivedRecoveredHistoryRetentionReceipt =
                        codec::from_bytes_canonical(&existing)
                            .map_err(|e| TransactionError::Invalid(e.to_string()))?;
                    if existing != receipt {
                        return Err(TransactionError::Invalid(
                            "conflicting aft archived recovered-history retention receipt already published for the same archived checkpoint"
                                .into(),
                        ));
                    }
                    let existing_hash =
                        canonical_archived_recovered_history_retention_receipt_hash(&existing)
                            .map_err(TransactionError::Invalid)?;
                    let receipt_hash =
                        canonical_archived_recovered_history_retention_receipt_hash(&receipt)
                            .map_err(TransactionError::Invalid)?;
                    if existing_hash != receipt_hash {
                        return Err(TransactionError::Invalid(
                            "conflicting aft archived recovered-history retention receipt hash published for the same archived checkpoint"
                                .into(),
                        ));
                    }
                    return Ok(());
                }

                state.insert(&key, &receipt_bytes)?;
                Ok(())
            }
            "publish_aft_missing_recovery_share@v1" => {
                let missing: MissingRecoveryShare = codec::from_bytes_canonical(params)?;
                if missing.height == 0
                    || missing.witness_manifest_hash == [0u8; 32]
                    || missing.recovery_capsule_hash == [0u8; 32]
                    || missing.recovery_window_close_ms == 0
                {
                    return Err(TransactionError::Invalid(
                        "aft missing recovery share requires non-zero height, witness manifest, capsule, and recovery window"
                            .into(),
                    ));
                }
                let certificate = Self::load_recovery_witness_certificate(
                    state,
                    missing.height,
                    &missing.witness_manifest_hash,
                )?
                .ok_or_else(|| {
                    TransactionError::Invalid(
                        "aft missing recovery share requires a published recovery witness certificate"
                            .into(),
                    )
                })?;
                if certificate.recovery_capsule_hash != missing.recovery_capsule_hash {
                    return Err(TransactionError::Invalid(
                        "aft missing recovery share must bind the witness certificate capsule"
                            .into(),
                    ));
                }
                if certificate.witness_manifest_hash != missing.witness_manifest_hash {
                    return Err(TransactionError::Invalid(
                        "aft missing recovery share must bind the witness manifest carried by the witness certificate"
                            .into(),
                    ));
                }
                let capsule =
                    Self::load_recovery_capsule(state, missing.height)?.ok_or_else(|| {
                        TransactionError::Invalid(
                            "aft missing recovery share requires a published recovery capsule"
                                .into(),
                        )
                    })?;
                let expected_capsule_hash =
                    canonical_recovery_capsule_hash(&capsule).map_err(TransactionError::Invalid)?;
                if missing.recovery_capsule_hash != expected_capsule_hash
                    || missing.recovery_window_close_ms != capsule.recovery_window_close_ms
                {
                    return Err(TransactionError::Invalid(
                        "aft missing recovery share must bind the published recovery capsule and recovery window"
                            .into(),
                    ));
                }
                if !Self::load_recovery_share_receipts(
                    state,
                    missing.height,
                    &missing.witness_manifest_hash,
                )?
                .is_empty()
                {
                    return Err(TransactionError::Invalid(
                        "cannot publish aft missing recovery share after a recovery receipt already exists"
                            .into(),
                    ));
                }
                let key =
                    aft_missing_recovery_share_key(missing.height, &missing.witness_manifest_hash);
                if let Some(existing) = Self::load_missing_recovery_share(
                    state,
                    missing.height,
                    &missing.witness_manifest_hash,
                )? {
                    if existing != missing {
                        return Err(TransactionError::Invalid(
                            "conflicting aft missing recovery share already published for witness manifest"
                                .into(),
                        ));
                    }
                    return Ok(());
                }
                state.insert(
                    &key,
                    &codec::to_bytes_canonical(&missing)
                        .map_err(TransactionError::Serialization)?,
                )?;
                Self::materialize_recovery_impossible_abort_if_needed(state, missing.height)?;
                Ok(())
            }
            "publish_aft_canonical_order_artifact_bundle@v1" => {
                let bundle: CanonicalOrderPublicationBundle = codec::from_bytes_canonical(params)?;
                let bulletin_close = verify_canonical_order_publication_bundle(&bundle)
                    .map_err(TransactionError::Invalid)?;
                self.materialize_canonical_order_publication_bundle(
                    state,
                    &bundle,
                    &bulletin_close,
                    ctx,
                )
            }
            "publish_aft_canonical_order_abort@v1" => {
                let abort: CanonicalOrderAbort = codec::from_bytes_canonical(params)?;
                if abort.height == 0 {
                    return Err(TransactionError::Invalid(
                        "aft canonical-order abort requires non-zero height".into(),
                    ));
                }
                Self::materialize_canonical_order_abort(state, abort)?;
                Ok(())
            }
            "publish_aft_canonical_collapse_object@v1" => {
                let collapse: CanonicalCollapseObject = codec::from_bytes_canonical(params)?;
                Self::materialize_canonical_collapse_object(state, collapse)
            }
            "publish_aft_order_certificate@v1" => {
                let _certificate: CanonicalOrderCertificate = codec::from_bytes_canonical(params)?;
                Err(TransactionError::Invalid(
                    "publish_aft_order_certificate@v1 is retired; publish_aft_canonical_order_artifact_bundle@v1 is required for positive canonical-order admission".into(),
                ))
            }
            "report_aft_omission@v1" => {
                let omission: OmissionProof = codec::from_bytes_canonical(params)?;
                if omission.height == 0
                    || omission.tx_hash == [0u8; 32]
                    || omission.offender_account_id == AccountId::default()
                {
                    return Err(TransactionError::Invalid(
                        "aft omission proof requires non-zero height, offender, and tx hash".into(),
                    ));
                }
                state.insert(
                    &aft_omission_proof_key(omission.height, &omission.tx_hash),
                    &codec::to_bytes_canonical(&omission)
                        .map_err(TransactionError::Serialization)?,
                )?;
                let existing_certificate =
                    Self::load_canonical_order_certificate(state, omission.height)
                        .map_err(TransactionError::State)?;
                let existing_close = Self::load_canonical_bulletin_close(state, omission.height)
                    .map_err(TransactionError::State)?;
                let abort = Self::build_canonical_order_abort(
                    omission.height,
                    CanonicalOrderAbortReason::OmissionDominated,
                    omission.details.clone(),
                    existing_certificate.as_ref(),
                    existing_close.as_ref(),
                );
                Self::materialize_canonical_order_abort(state, abort)?;
                let report = Self::omission_failure_report(&omission)?;
                Self::apply_accountable_fault_report(
                    state,
                    report,
                    ctx.block_height,
                    self.config.apply_accountable_membership_updates,
                )?;
                Ok(())
            }
            "anchor_guardian_checkpoint@v1" => {
                let checkpoint: GuardianLogCheckpoint = codec::from_bytes_canonical(params)?;
                state.insert(
                    &[
                        GUARDIAN_REGISTRY_CHECKPOINT_PREFIX,
                        checkpoint.log_id.as_bytes(),
                    ]
                    .concat(),
                    &codec::to_bytes_canonical(&checkpoint)
                        .map_err(TransactionError::Serialization)?,
                )?;
                Ok(())
            }
            "report_guardian_equivocation@v1" => {
                let proof: ProofOfDivergence = codec::from_bytes_canonical(params)?;
                state.insert(
                    &[
                        GUARDIAN_REGISTRY_EQUIVOCATION_PREFIX,
                        proof.offender.as_ref(),
                    ]
                    .concat(),
                    &codec::to_bytes_canonical(&proof).map_err(TransactionError::Serialization)?,
                )?;
                Ok(())
            }
            "report_guardian_witness_fault@v1" => {
                let evidence: GuardianWitnessFaultEvidence = codec::from_bytes_canonical(params)?;
                state.insert(
                    &guardian_registry_witness_fault_key(&evidence.evidence_id),
                    &codec::to_bytes_canonical(&evidence)
                        .map_err(TransactionError::Serialization)?,
                )?;
                Ok(())
            }
            _ => Err(TransactionError::Unsupported(format!(
                "GuardianRegistry does not support method '{}'",
                method
            ))),
        }
    }
}

#[async_trait]
impl UpgradableService for GuardianRegistry {
    async fn prepare_upgrade(&self, _new_module_wasm: &[u8]) -> Result<Vec<u8>, UpgradeError> {
        Ok(Vec::new())
    }

    async fn complete_upgrade(&self, _snapshot: &[u8]) -> Result<(), UpgradeError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ioi_api::services::access::ServiceDirectory;
    use ioi_api::state::StateScanIter;
    use ioi_api::transaction::context::TxContext;
    use ioi_types::app::{
        aft_archived_recovered_history_checkpoint_hash_key,
        aft_archived_recovered_history_profile_activation_height_key,
        aft_archived_recovered_history_profile_activation_key,
        aft_archived_recovered_history_profile_hash_key,
        aft_archived_recovered_history_retention_receipt_key,
        aft_archived_recovered_history_segment_hash_key,
        aft_archived_recovered_history_segment_key, aft_archived_recovered_restart_page_key,
        aft_bulletin_availability_certificate_key, aft_bulletin_commitment_key,
        aft_bulletin_entry_key, aft_canonical_bulletin_close_key,
        aft_canonical_collapse_object_key, aft_canonical_order_abort_key,
        aft_missing_recovery_share_key, aft_omission_proof_key, aft_order_certificate_key,
        aft_publication_frontier_contradiction_key, aft_publication_frontier_key,
        aft_recovered_publication_bundle_key, aft_recovery_capsule_key,
        aft_recovery_share_material_key, aft_recovery_share_receipt_key,
        aft_recovery_witness_certificate_key, archived_recovered_history_retained_through_height,
        build_archived_recovered_history_checkpoint, build_archived_recovered_history_profile,
        build_archived_recovered_history_profile_activation,
        build_archived_recovered_history_retention_receipt,
        build_archived_recovered_history_segment, build_archived_recovered_restart_page,
        build_bulletin_surface_entries, build_canonical_bulletin_close,
        build_committed_surface_canonical_order_certificate,
        canonical_archived_recovered_history_checkpoint_hash,
        canonical_archived_recovered_history_profile_hash,
        canonical_archived_recovered_history_retention_receipt_hash,
        canonical_archived_recovered_history_segment_hash,
        canonical_asymptote_observer_canonical_close_hash, canonical_bulletin_close_hash,
        canonical_order_certificate_hash, canonical_order_publication_bundle_hash,
        canonical_recoverable_slot_payload_v4_hash, canonical_recoverable_slot_payload_v5_hash,
        canonical_recovery_capsule_hash, canonical_transaction_root_from_hashes,
        canonical_validator_sets_hash, canonicalize_transactions_for_header,
        derive_canonical_order_execution_object, encode_coded_recovery_shards,
        guardian_registry_effect_nullifier_key, guardian_registry_effect_verifier_key,
        guardian_registry_log_key, guardian_registry_observer_canonical_abort_key,
        guardian_registry_observer_canonical_close_key,
        guardian_registry_observer_challenge_commitment_key,
        guardian_registry_observer_challenge_key,
        guardian_registry_observer_transcript_commitment_key,
        guardian_registry_observer_transcript_key, guardian_registry_sealed_effect_key,
        read_validator_sets, recover_canonical_order_publication_bundle_from_share_materials,
        recover_full_canonical_order_surface_from_share_materials,
        recovered_certified_header_prefix, recovered_restart_block_header_entry,
        write_validator_sets, AccountId, ArchivedRecoveredHistoryCheckpoint,
        ArchivedRecoveredHistoryCheckpointUpdateRule, ArchivedRecoveredHistoryProfile,
        ArchivedRecoveredHistoryProfileActivation, ArchivedRecoveredHistoryRetentionReceipt,
        ArchivedRecoveredHistorySegment, ArchivedRecoveredRestartPage, AsymptoteObserverAssignment,
        AsymptoteObserverCanonicalAbort, AsymptoteObserverCanonicalClose,
        AsymptoteObserverChallenge, AsymptoteObserverChallengeCommitment,
        AsymptoteObserverChallengeKind, AsymptoteObserverObservationRequest,
        AsymptoteObserverSealingMode, AsymptoteObserverStatement, AsymptoteObserverTranscript,
        AsymptoteObserverTranscriptCommitment, AsymptoteObserverVerdict, BlockHeader,
        BulletinAvailabilityCertificate, BulletinCommitment, BulletinSurfaceEntry,
        CanonicalBulletinClose, CanonicalCollapseObject, CanonicalOrderAbort,
        CanonicalOrderAbortReason, CanonicalOrderCertificate, CanonicalOrderProof,
        CanonicalOrderProofSystem, CanonicalOrderPublicationBundle, ChainId, ChainTransaction,
        EffectProofSystem, EffectProofVerifierDescriptor, GuardianCommitteeMember,
        GuardianQuorumCertificate, GuardianTransparencyLogDescriptor, GuardianWitnessEpochSeed,
        MissingRecoveryShare, OmissionProof, PublicationFrontier, PublicationFrontierContradiction,
        PublicationFrontierContradictionKind, QuorumCertificate, RecoverableSlotPayloadV3,
        RecoveredPublicationBundle, RecoveredSegmentFoldCursor, RecoveryCapsule,
        RecoveryCodingDescriptor, RecoveryCodingFamily, RecoveryShareMaterial,
        RecoveryShareReceipt, RecoveryWitnessCertificate, SealedEffectClass, SealedEffectRecord,
        SignHeader, SignatureProof, SignatureSuite, StateRoot, SystemPayload, SystemTransaction,
        ValidatorSetV1, ValidatorSetsV1, ValidatorV1,
        AFT_ACTIVE_ARCHIVED_RECOVERED_HISTORY_PROFILE_KEY,
        AFT_LATEST_ARCHIVED_RECOVERED_HISTORY_CHECKPOINT_KEY,
        AFT_LATEST_ARCHIVED_RECOVERED_HISTORY_PROFILE_ACTIVATION_KEY,
    };
    use ioi_types::keys::{EVIDENCE_REGISTRY_KEY, QUARANTINED_VALIDATORS_KEY, VALIDATOR_SET_KEY};
    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::Arc;

    #[derive(Default)]
    struct MockState {
        data: BTreeMap<Vec<u8>, Vec<u8>>,
    }

    impl StateAccess for MockState {
        fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StateError> {
            Ok(self.data.get(key).cloned())
        }

        fn insert(&mut self, key: &[u8], value: &[u8]) -> Result<(), StateError> {
            self.data.insert(key.to_vec(), value.to_vec());
            Ok(())
        }

        fn delete(&mut self, key: &[u8]) -> Result<(), StateError> {
            self.data.remove(key);
            Ok(())
        }

        fn batch_set(&mut self, updates: &[(Vec<u8>, Vec<u8>)]) -> Result<(), StateError> {
            for (key, value) in updates {
                self.insert(key, value)?;
            }
            Ok(())
        }

        fn batch_get(&self, keys: &[Vec<u8>]) -> Result<Vec<Option<Vec<u8>>>, StateError> {
            keys.iter().map(|key| self.get(key)).collect()
        }

        fn batch_apply(
            &mut self,
            inserts: &[(Vec<u8>, Vec<u8>)],
            deletes: &[Vec<u8>],
        ) -> Result<(), StateError> {
            for key in deletes {
                self.delete(key)?;
            }
            for (key, value) in inserts {
                self.insert(key, value)?;
            }
            Ok(())
        }

        fn prefix_scan(&self, prefix: &[u8]) -> Result<StateScanIter<'_>, StateError> {
            let rows: Vec<_> = self
                .data
                .iter()
                .filter(|(key, _)| key.starts_with(prefix))
                .map(|(key, value)| Ok((Arc::from(key.as_slice()), Arc::from(value.as_slice()))))
                .collect();
            Ok(Box::new(rows.into_iter()))
        }
    }

    fn with_ctx<F>(f: F)
    where
        F: FnOnce(&mut TxContext<'_>),
    {
        let services = ServiceDirectory::new(Vec::new());
        let mut ctx = TxContext {
            block_height: 42,
            block_timestamp: 1_750_000_000_000_000_000,
            chain_id: ChainId(1),
            signer_account_id: AccountId([7u8; 32]),
            services: &services,
            simulation: false,
            is_internal: false,
        };
        f(&mut ctx);
    }

    fn run_async<F: std::future::Future<Output = T>, T>(future: F) -> T {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
            .block_on(future)
    }

    fn production_registry() -> GuardianRegistry {
        GuardianRegistry::new(GuardianRegistryParams {
            enabled: true,
            ..Default::default()
        })
    }

    fn production_registry_without_accountable_membership_updates() -> GuardianRegistry {
        GuardianRegistry::new(GuardianRegistryParams {
            enabled: true,
            apply_accountable_membership_updates: false,
            ..Default::default()
        })
    }

    fn validator(account: u8, weight: u128) -> ValidatorV1 {
        ValidatorV1 {
            account_id: AccountId([account; 32]),
            weight,
            consensus_key: Default::default(),
        }
    }

    fn sample_recovery_capsule(height: u64) -> RecoveryCapsule {
        RecoveryCapsule {
            height,
            coding: xor_recovery_coding(3, 2),
            recovery_committee_root_hash: [height as u8 + 1; 32],
            payload_commitment_hash: [height as u8 + 2; 32],
            coding_root_hash: [height as u8 + 3; 32],
            recovery_window_close_ms: 1_750_002_000_000 + height,
        }
    }

    fn xor_recovery_coding(share_count: u16, recovery_threshold: u16) -> RecoveryCodingDescriptor {
        RecoveryCodingDescriptor {
            family: RecoveryCodingFamily::SystematicXorKOfKPlus1V1,
            share_count,
            recovery_threshold,
        }
    }

    fn gf256_recovery_coding(
        share_count: u16,
        recovery_threshold: u16,
    ) -> RecoveryCodingDescriptor {
        RecoveryCodingDescriptor {
            family: RecoveryCodingFamily::SystematicGf256KOfNV1,
            share_count,
            recovery_threshold,
        }
    }

    fn nonzero_test_byte(value: u8) -> u8 {
        if value == 0 {
            1
        } else {
            value
        }
    }

    fn sample_recovery_witness_certificate(
        capsule: &RecoveryCapsule,
        witness_manifest_hash: [u8; 32],
        share_commitment_hash: [u8; 32],
    ) -> RecoveryWitnessCertificate {
        RecoveryWitnessCertificate {
            height: capsule.height,
            epoch: 19,
            witness_manifest_hash,
            recovery_capsule_hash: canonical_recovery_capsule_hash(capsule)
                .expect("recovery capsule hash"),
            share_commitment_hash,
        }
    }

    fn sample_recovered_publication_bundle_fixture_with_scheme(
        height: u64,
        seed: u8,
        coding: RecoveryCodingDescriptor,
        support_share_indices: &[u16],
    ) -> (
        RecoveryCapsule,
        Vec<RecoveryWitnessCertificate>,
        Vec<RecoveryShareMaterial>,
        RecoveredPublicationBundle,
    ) {
        sample_recovered_publication_bundle_fixture_with_scheme_and_optional_omission(
            height,
            seed,
            coding,
            support_share_indices,
            None,
            None,
        )
    }

    fn sample_recovered_publication_bundle_fixture_with_scheme_and_optional_omission(
        height: u64,
        seed: u8,
        coding: RecoveryCodingDescriptor,
        support_share_indices: &[u16],
        parent_block_hash: Option<[u8; 32]>,
        omission: Option<(AccountId, [u8; 32])>,
    ) -> (
        RecoveryCapsule,
        Vec<RecoveryWitnessCertificate>,
        Vec<RecoveryShareMaterial>,
        RecoveredPublicationBundle,
    ) {
        let share_count = coding.share_count;
        let recovery_threshold = coding.recovery_threshold;
        assert!(coding
            .family_contract()
            .expect("recovery-family contract")
            .supports_coded_payload_reconstruction());
        assert_eq!(support_share_indices.len(), usize::from(recovery_threshold));

        let mut header = BlockHeader {
            height,
            view: 4,
            parent_hash: parent_block_hash.unwrap_or([nonzero_test_byte(seed.wrapping_add(1)); 32]),
            parent_state_root: StateRoot(vec![nonzero_test_byte(seed.wrapping_add(2)); 32]),
            state_root: StateRoot(vec![nonzero_test_byte(seed.wrapping_add(3)); 32]),
            transactions_root: vec![],
            timestamp: 1_750_010_000 + height,
            timestamp_ms: (1_750_010_000 + height) * 1_000,
            gas_used: 0,
            validator_set: Vec::new(),
            producer_account_id: AccountId([nonzero_test_byte(seed.wrapping_add(4)); 32]),
            producer_key_suite: SignatureSuite::ED25519,
            producer_pubkey_hash: [nonzero_test_byte(seed.wrapping_add(5)); 32],
            producer_pubkey: Vec::new(),
            signature: Vec::new(),
            oracle_counter: 0,
            oracle_trace_hash: [0u8; 32],
            parent_qc: QuorumCertificate::default(),
            previous_canonical_collapse_commitment_hash: [0u8; 32],
            canonical_collapse_extension_certificate: None,
            publication_frontier: None,
            guardian_certificate: None,
            sealed_finality_proof: None,
            canonical_order_certificate: None,
            timeout_certificate: None,
        };
        let tx_one = ChainTransaction::System(Box::new(SystemTransaction {
            header: SignHeader {
                account_id: AccountId([nonzero_test_byte(seed.wrapping_add(10)); 32]),
                nonce: 1,
                chain_id: ChainId(1),
                tx_version: 1,
                session_auth: None,
            },
            payload: SystemPayload::CallService {
                service_id: "guardian_registry".into(),
                method: "publish_aft_bulletin_commitment@v1".into(),
                params: vec![seed],
            },
            signature_proof: SignatureProof::default(),
        }));
        let tx_two = ChainTransaction::System(Box::new(SystemTransaction {
            header: SignHeader {
                account_id: AccountId([nonzero_test_byte(seed.wrapping_add(11)); 32]),
                nonce: 1,
                chain_id: ChainId(1),
                tx_version: 1,
                session_auth: None,
            },
            payload: SystemPayload::CallService {
                service_id: "guardian_registry".into(),
                method: "publish_aft_canonical_order_artifact_bundle@v1".into(),
                params: vec![seed.wrapping_add(1)],
            },
            signature_proof: SignatureProof::default(),
        }));
        let ordered_transactions = canonicalize_transactions_for_header(&header, &[tx_one, tx_two])
            .expect("canonicalized transactions");
        let tx_hashes: Vec<[u8; 32]> = ordered_transactions
            .iter()
            .map(|tx| tx.hash().expect("tx hash"))
            .collect();
        header.transactions_root =
            canonical_transaction_root_from_hashes(&tx_hashes).expect("transactions root");
        let mut certificate =
            build_committed_surface_canonical_order_certificate(&header, &ordered_transactions)
                .expect("build committed-surface certificate");
        if let Some((offender_account_id, tx_hash)) = omission {
            certificate.omission_proofs = vec![OmissionProof {
                height,
                offender_account_id,
                tx_hash,
                bulletin_root: certificate.bulletin_commitment.bulletin_root,
                details:
                    "recovered publication bundle omission remains decisive without membership penalties"
                        .into(),
            }];
        }
        header.canonical_order_certificate = Some(certificate.clone());
        let publication_bundle = if certificate.omission_proofs.is_empty() {
            let execution_object =
                derive_canonical_order_execution_object(&header, &ordered_transactions)
                    .expect("derive canonical order execution object");
            CanonicalOrderPublicationBundle {
                bulletin_commitment: execution_object.bulletin_commitment.clone(),
                bulletin_entries: execution_object.bulletin_entries.clone(),
                bulletin_availability_certificate: execution_object
                    .bulletin_availability_certificate
                    .clone(),
                canonical_order_certificate: execution_object.canonical_order_certificate.clone(),
            }
        } else {
            CanonicalOrderPublicationBundle {
                bulletin_commitment: certificate.bulletin_commitment.clone(),
                bulletin_entries: build_bulletin_surface_entries(height, &ordered_transactions)
                    .expect("build bulletin surface entries"),
                bulletin_availability_certificate: certificate
                    .bulletin_availability_certificate
                    .clone(),
                canonical_order_certificate: certificate.clone(),
            }
        };
        let block_hash = header.hash().expect("header hash");
        let block_commitment_hash: [u8; 32] = block_hash
            .as_slice()
            .try_into()
            .expect("32-byte block hash");
        let payload = RecoverableSlotPayloadV3 {
            height,
            view: header.view,
            producer_account_id: header.producer_account_id,
            block_commitment_hash,
            parent_block_hash: header.parent_hash,
            canonical_order_certificate: certificate,
            ordered_transaction_bytes: ordered_transactions
                .iter()
                .map(|transaction| codec::to_bytes_canonical(transaction).expect("encode tx"))
                .collect(),
            canonical_order_publication_bundle_bytes: codec::to_bytes_canonical(
                &publication_bundle,
            )
            .expect("encode publication bundle"),
        };
        let payload_bytes = codec::to_bytes_canonical(&payload).expect("encode payload");
        let shard_bytes =
            encode_coded_recovery_shards(coding, &payload_bytes).expect("encode coded shards");
        assert_eq!(shard_bytes.len(), usize::from(share_count));
        let (payload_v4, _, bulletin_close) =
            ioi_types::app::lift_recoverable_slot_payload_v3_to_v4(&payload)
                .expect("lift recoverable payload v4");
        let (payload_v5, _, _, _) =
            ioi_types::app::lift_recoverable_slot_payload_v4_to_v5(&payload_v4)
                .expect("lift recoverable payload v5");

        let capsule = RecoveryCapsule {
            height,
            coding,
            recovery_committee_root_hash: [nonzero_test_byte(seed.wrapping_add(40)); 32],
            payload_commitment_hash: [nonzero_test_byte(seed.wrapping_add(41)); 32],
            coding_root_hash: [nonzero_test_byte(seed.wrapping_add(42)); 32],
            recovery_window_close_ms: 1_750_002_000_000 + height,
        };
        let witnesses = support_share_indices
            .iter()
            .enumerate()
            .map(|(offset, _)| {
                let mut witness_manifest_hash = [0u8; 32];
                witness_manifest_hash[..8].copy_from_slice(&height.to_be_bytes());
                witness_manifest_hash[8] = nonzero_test_byte((offset as u8).wrapping_add(1));
                witness_manifest_hash[9] = nonzero_test_byte(seed.wrapping_add(20 + offset as u8));
                witness_manifest_hash
            })
            .collect::<Vec<_>>();
        let share_commitments = support_share_indices
            .iter()
            .enumerate()
            .map(|(offset, _)| {
                let mut share_commitment_hash = [0u8; 32];
                share_commitment_hash[..8].copy_from_slice(&height.to_be_bytes());
                share_commitment_hash[8] = nonzero_test_byte((offset as u8).wrapping_add(1));
                share_commitment_hash[9] = nonzero_test_byte(seed.wrapping_add(30 + offset as u8));
                share_commitment_hash
            })
            .collect::<Vec<_>>();
        let certificates = witnesses
            .iter()
            .zip(share_commitments.iter())
            .map(|(witness_manifest_hash, share_commitment_hash)| {
                sample_recovery_witness_certificate(
                    &capsule,
                    *witness_manifest_hash,
                    *share_commitment_hash,
                )
            })
            .collect::<Vec<_>>();
        let materials = witnesses
            .iter()
            .zip(support_share_indices.iter())
            .zip(share_commitments.iter())
            .map(
                |((witness_manifest_hash, share_index), share_commitment_hash)| {
                    RecoveryShareMaterial {
                        height,
                        witness_manifest_hash: *witness_manifest_hash,
                        block_commitment_hash,
                        coding,
                        share_index: *share_index,
                        share_commitment_hash: *share_commitment_hash,
                        material_bytes: shard_bytes[usize::from(*share_index)].clone(),
                    }
                },
            )
            .collect::<Vec<_>>();
        let recovered = RecoveredPublicationBundle {
            height,
            block_commitment_hash,
            parent_block_commitment_hash: header.parent_hash,
            coding,
            supporting_witness_manifest_hashes: witnesses,
            recoverable_slot_payload_hash: canonical_recoverable_slot_payload_v4_hash(&payload_v4)
                .expect("payload hash"),
            recoverable_full_surface_hash: canonical_recoverable_slot_payload_v5_hash(&payload_v5)
                .expect("full surface hash"),
            canonical_order_publication_bundle_hash: canonical_order_publication_bundle_hash(
                &publication_bundle,
            )
            .expect("publication bundle hash"),
            canonical_bulletin_close_hash: canonical_bulletin_close_hash(&bulletin_close)
                .expect("bulletin close hash"),
        };
        (capsule, certificates, materials, recovered)
    }

    fn sample_recovered_publication_bundle_fixture_3_of_5_with_omission(
        height: u64,
        seed: u8,
        offender_account_id: AccountId,
        tx_hash: [u8; 32],
    ) -> (
        RecoveryCapsule,
        Vec<RecoveryWitnessCertificate>,
        Vec<RecoveryShareMaterial>,
        RecoveredPublicationBundle,
    ) {
        sample_recovered_publication_bundle_fixture_with_scheme_and_optional_omission(
            height,
            seed,
            gf256_recovery_coding(5, 3),
            &[0, 3, 4],
            None,
            Some((offender_account_id, tx_hash)),
        )
    }

    fn sample_recovered_publication_bundle_fixture(
        height: u64,
        seed: u8,
    ) -> (
        RecoveryCapsule,
        Vec<RecoveryWitnessCertificate>,
        Vec<RecoveryShareMaterial>,
        RecoveredPublicationBundle,
    ) {
        sample_recovered_publication_bundle_fixture_with_scheme(
            height,
            seed,
            gf256_recovery_coding(4, 2),
            &[1, 3],
        )
    }

    fn sample_recovered_publication_bundle_fixture_3_of_5(
        height: u64,
        seed: u8,
    ) -> (
        RecoveryCapsule,
        Vec<RecoveryWitnessCertificate>,
        Vec<RecoveryShareMaterial>,
        RecoveredPublicationBundle,
    ) {
        sample_recovered_publication_bundle_fixture_with_scheme(
            height,
            seed,
            gf256_recovery_coding(5, 3),
            &[0, 3, 4],
        )
    }

    fn sample_recovered_publication_bundle_fixture_4_of_6(
        height: u64,
        seed: u8,
    ) -> (
        RecoveryCapsule,
        Vec<RecoveryWitnessCertificate>,
        Vec<RecoveryShareMaterial>,
        RecoveredPublicationBundle,
    ) {
        sample_recovered_publication_bundle_fixture_with_scheme(
            height,
            seed,
            gf256_recovery_coding(6, 4),
            &[0, 2, 4, 5],
        )
    }

    fn sample_recovered_publication_bundle_fixture_3_of_7(
        height: u64,
        seed: u8,
    ) -> (
        RecoveryCapsule,
        Vec<RecoveryWitnessCertificate>,
        Vec<RecoveryShareMaterial>,
        RecoveredPublicationBundle,
    ) {
        sample_recovered_publication_bundle_fixture_with_scheme(
            height,
            seed,
            gf256_recovery_coding(7, 3),
            &[0, 3, 6],
        )
    }

    fn sample_recovered_publication_bundle_fixture_3_of_7_with_parent(
        height: u64,
        seed: u8,
        parent_block_hash: [u8; 32],
    ) -> (
        RecoveryCapsule,
        Vec<RecoveryWitnessCertificate>,
        Vec<RecoveryShareMaterial>,
        RecoveredPublicationBundle,
    ) {
        sample_recovered_publication_bundle_fixture_with_scheme_and_optional_omission(
            height,
            seed,
            gf256_recovery_coding(7, 3),
            &[0, 3, 6],
            Some(parent_block_hash),
            None,
        )
    }

    fn sample_recovered_publication_bundle_fixture_3_of_7_with_parent_and_omission(
        height: u64,
        seed: u8,
        parent_block_hash: [u8; 32],
        offender_account_id: AccountId,
        tx_hash: [u8; 32],
    ) -> (
        RecoveryCapsule,
        Vec<RecoveryWitnessCertificate>,
        Vec<RecoveryShareMaterial>,
        RecoveredPublicationBundle,
    ) {
        sample_recovered_publication_bundle_fixture_with_scheme_and_optional_omission(
            height,
            seed,
            gf256_recovery_coding(7, 3),
            &[0, 3, 6],
            Some(parent_block_hash),
            Some((offender_account_id, tx_hash)),
        )
    }

    fn sample_recovered_publication_bundle_fixture_4_of_7(
        height: u64,
        seed: u8,
    ) -> (
        RecoveryCapsule,
        Vec<RecoveryWitnessCertificate>,
        Vec<RecoveryShareMaterial>,
        RecoveredPublicationBundle,
    ) {
        sample_recovered_publication_bundle_fixture_with_scheme(
            height,
            seed,
            gf256_recovery_coding(7, 4),
            &[0, 2, 4, 6],
        )
    }

    fn seed_previous_canonical_collapse_placeholder_if_absent(
        state: &mut MockState,
        height: u64,
        seed: u8,
    ) {
        if height <= 1 {
            return;
        }
        let key = aft_canonical_collapse_object_key(height - 1);
        if state.get(&key).unwrap().is_some() {
            return;
        }
        let previous = CanonicalCollapseObject {
            height: height - 1,
            previous_canonical_collapse_commitment_hash: [0u8; 32],
            continuity_accumulator_hash: [0u8; 32],
            continuity_recursive_proof: Default::default(),
            ordering: ioi_types::app::CanonicalOrderingCollapse {
                height: height - 1,
                kind: CanonicalCollapseKind::Close,
                bulletin_commitment_hash: [seed; 32],
                bulletin_availability_certificate_hash: [seed.wrapping_add(1); 32],
                bulletin_close_hash: [seed.wrapping_add(2); 32],
                canonical_order_certificate_hash: [seed.wrapping_add(3); 32],
            },
            sealing: None,
            transactions_root_hash: [seed.wrapping_add(4); 32],
            resulting_state_root_hash: [seed.wrapping_add(5); 32],
            archived_recovered_history_checkpoint_hash: [0u8; 32],
            archived_recovered_history_profile_activation_hash: [0u8; 32],
            archived_recovered_history_retention_receipt_hash: [0u8; 32],
        };
        state
            .insert(&key, &codec::to_bytes_canonical(&previous).unwrap())
            .unwrap();
    }

    fn assert_conflicting_recovered_publication_bundles_materialize_abort(
        capsule: RecoveryCapsule,
        certificates: Vec<RecoveryWitnessCertificate>,
        materials: Vec<RecoveryShareMaterial>,
        recovered: RecoveredPublicationBundle,
        conflicting_certificates: Vec<RecoveryWitnessCertificate>,
        conflicting_materials: Vec<RecoveryShareMaterial>,
        conflicting_recovered: RecoveredPublicationBundle,
    ) {
        let registry = production_registry();
        let mut state = MockState::default();
        seed_previous_canonical_collapse_placeholder_if_absent(&mut state, recovered.height, 0xA0);
        with_ctx(|ctx| {
            run_async(registry.handle_service_call(
                &mut state,
                "publish_aft_recovery_capsule@v1",
                &codec::to_bytes_canonical(&capsule).unwrap(),
                ctx,
            ))
            .unwrap();
            for certificate in &certificates {
                run_async(registry.handle_service_call(
                    &mut state,
                    "publish_aft_recovery_witness_certificate@v1",
                    &codec::to_bytes_canonical(certificate).unwrap(),
                    ctx,
                ))
                .unwrap();
            }
            for material in &materials {
                let receipt = material.to_recovery_share_receipt();
                run_async(registry.handle_service_call(
                    &mut state,
                    "publish_aft_recovery_share_receipt@v1",
                    &codec::to_bytes_canonical(&receipt).unwrap(),
                    ctx,
                ))
                .unwrap();
                run_async(registry.handle_service_call(
                    &mut state,
                    "publish_aft_recovery_share_material@v1",
                    &codec::to_bytes_canonical(material).unwrap(),
                    ctx,
                ))
                .unwrap();
            }
            run_async(registry.handle_service_call(
                &mut state,
                "publish_aft_recovered_publication_bundle@v1",
                &codec::to_bytes_canonical(&recovered).unwrap(),
                ctx,
            ))
            .unwrap();

            for certificate in &conflicting_certificates {
                run_async(registry.handle_service_call(
                    &mut state,
                    "publish_aft_recovery_witness_certificate@v1",
                    &codec::to_bytes_canonical(certificate).unwrap(),
                    ctx,
                ))
                .unwrap();
            }
            for material in &conflicting_materials {
                let receipt = material.to_recovery_share_receipt();
                run_async(registry.handle_service_call(
                    &mut state,
                    "publish_aft_recovery_share_receipt@v1",
                    &codec::to_bytes_canonical(&receipt).unwrap(),
                    ctx,
                ))
                .unwrap();
                run_async(registry.handle_service_call(
                    &mut state,
                    "publish_aft_recovery_share_material@v1",
                    &codec::to_bytes_canonical(material).unwrap(),
                    ctx,
                ))
                .unwrap();
            }
            run_async(registry.handle_service_call(
                &mut state,
                "publish_aft_recovered_publication_bundle@v1",
                &codec::to_bytes_canonical(&conflicting_recovered).unwrap(),
                ctx,
            ))
            .unwrap();
        });

        let abort = GuardianRegistry::load_canonical_order_abort(&state, recovered.height)
            .unwrap()
            .expect("conflicting recovered bundles should materialize an abort");
        assert_eq!(
            abort.reason,
            CanonicalOrderAbortReason::RecoverySupportConflict
        );
        assert!(
            GuardianRegistry::load_canonical_bulletin_close(&state, recovered.height)
                .unwrap()
                .is_none()
        );
        assert_eq!(
            GuardianRegistry::load_recovered_publication_bundles(
                &state,
                recovered.height,
                &recovered.block_commitment_hash,
            )
            .unwrap(),
            vec![recovered.clone()]
        );
        assert_eq!(
            GuardianRegistry::load_recovered_publication_bundles(
                &state,
                conflicting_recovered.height,
                &conflicting_recovered.block_commitment_hash,
            )
            .unwrap(),
            vec![conflicting_recovered.clone()]
        );
    }

    fn publish_recovered_publication_fixture(
        registry: &GuardianRegistry,
        state: &mut MockState,
        capsule: &RecoveryCapsule,
        certificates: &[RecoveryWitnessCertificate],
        materials: &[RecoveryShareMaterial],
        recovered: &RecoveredPublicationBundle,
    ) {
        seed_previous_canonical_collapse_placeholder_if_absent(state, recovered.height, 0x90);
        with_ctx(|ctx| {
            run_async(registry.handle_service_call(
                state,
                "publish_aft_recovery_capsule@v1",
                &codec::to_bytes_canonical(capsule).unwrap(),
                ctx,
            ))
            .unwrap();
            for certificate in certificates {
                run_async(registry.handle_service_call(
                    state,
                    "publish_aft_recovery_witness_certificate@v1",
                    &codec::to_bytes_canonical(certificate).unwrap(),
                    ctx,
                ))
                .unwrap();
            }
            for material in materials {
                let receipt = material.to_recovery_share_receipt();
                run_async(registry.handle_service_call(
                    state,
                    "publish_aft_recovery_share_receipt@v1",
                    &codec::to_bytes_canonical(&receipt).unwrap(),
                    ctx,
                ))
                .unwrap();
                run_async(registry.handle_service_call(
                    state,
                    "publish_aft_recovery_share_material@v1",
                    &codec::to_bytes_canonical(material).unwrap(),
                    ctx,
                ))
                .unwrap();
            }
            run_async(registry.handle_service_call(
                state,
                "publish_aft_recovered_publication_bundle@v1",
                &codec::to_bytes_canonical(recovered).unwrap(),
                ctx,
            ))
            .unwrap();
        });
    }

    #[test]
    fn publishing_archived_recovered_history_segments_persists_deterministic_chain_and_loads_by_start(
    ) {
        let registry = production_registry();
        let mut state = MockState::default();
        let _profile = seed_active_archived_recovered_history_profile(&mut state);
        let (_, _, _, recovered_a) = sample_recovered_publication_bundle_fixture(90, 0x31);
        let (_, _, _, recovered_b) = sample_recovered_publication_bundle_fixture(91, 0x32);

        let previous_segment = build_archived_recovered_history_segment(
            std::slice::from_ref(&recovered_a),
            None,
            None,
            &sample_archived_recovered_history_profile(),
            &sample_bootstrap_archived_recovered_history_profile_activation(
                &sample_archived_recovered_history_profile(),
            ),
        )
        .expect("previous archived segment");
        let current_segment = build_archived_recovered_history_segment(
            std::slice::from_ref(&recovered_b),
            Some(&previous_segment),
            None,
            &sample_archived_recovered_history_profile(),
            &sample_bootstrap_archived_recovered_history_profile_activation(
                &sample_archived_recovered_history_profile(),
            ),
        )
        .expect("current archived segment");

        with_ctx(|ctx| {
            run_async(registry.handle_service_call(
                &mut state,
                "publish_aft_archived_recovered_history_segment@v1",
                &codec::to_bytes_canonical(&previous_segment).unwrap(),
                ctx,
            ))
            .unwrap();
            run_async(registry.handle_service_call(
                &mut state,
                "publish_aft_archived_recovered_history_segment@v1",
                &codec::to_bytes_canonical(&current_segment).unwrap(),
                ctx,
            ))
            .unwrap();
        });

        assert_eq!(
            GuardianRegistry::load_archived_recovered_history_segment(&state, 90, 90).unwrap(),
            Some(previous_segment.clone())
        );
        assert_eq!(
            GuardianRegistry::load_archived_recovered_history_segment(&state, 91, 91).unwrap(),
            Some(current_segment.clone())
        );
        assert_eq!(
            GuardianRegistry::load_archived_recovered_history_segments_for_start(&state, 91)
                .unwrap(),
            vec![current_segment.clone()]
        );
        let previous_hash = canonical_archived_recovered_history_segment_hash(&previous_segment)
            .expect("previous archived segment hash");
        let current_hash = canonical_archived_recovered_history_segment_hash(&current_segment)
            .expect("current archived segment hash");
        assert_eq!(
            current_segment.previous_archived_segment_hash,
            previous_hash
        );
        assert_eq!(
            GuardianRegistry::load_archived_recovered_history_segment_by_hash(
                &state,
                &previous_hash,
            )
            .unwrap(),
            Some(previous_segment.clone())
        );
        assert_eq!(
            GuardianRegistry::load_archived_recovered_history_segment_by_hash(
                &state,
                &current_hash
            )
            .unwrap(),
            Some(current_segment.clone())
        );
        assert_eq!(
            GuardianRegistry::load_previous_archived_recovered_history_segment(
                &state,
                &current_segment,
            )
            .unwrap(),
            Some(previous_segment)
        );
        assert_eq!(
            state
                .get(&aft_archived_recovered_history_segment_hash_key(
                    &current_hash
                ))
                .unwrap()
                .is_some(),
            true
        );
    }

    #[test]
    fn publishing_conflicting_archived_recovered_history_segment_for_same_range_rejects_conflicting_overlap(
    ) {
        let registry = production_registry();
        let mut state = MockState::default();
        let _profile = seed_active_archived_recovered_history_profile(&mut state);
        let (_, _, _, recovered) = sample_recovered_publication_bundle_fixture(92, 0x41);
        let segment = build_archived_recovered_history_segment(
            std::slice::from_ref(&recovered),
            None,
            None,
            &sample_archived_recovered_history_profile(),
            &sample_bootstrap_archived_recovered_history_profile_activation(
                &sample_archived_recovered_history_profile(),
            ),
        )
        .expect("archived segment");
        let mut conflicting_segment = segment.clone();
        conflicting_segment.overlap_start_height = conflicting_segment.start_height;
        conflicting_segment.overlap_end_height = conflicting_segment.end_height;
        conflicting_segment.overlap_root_hash = [0xAB; 32];

        with_ctx(|ctx| {
            run_async(registry.handle_service_call(
                &mut state,
                "publish_aft_archived_recovered_history_segment@v1",
                &codec::to_bytes_canonical(&segment).unwrap(),
                ctx,
            ))
            .unwrap();
            let error = run_async(registry.handle_service_call(
                &mut state,
                "publish_aft_archived_recovered_history_segment@v1",
                &codec::to_bytes_canonical(&conflicting_segment).unwrap(),
                ctx,
            ))
            .expect_err("conflicting overlap on the same archived range should fail");
            assert!(error
                .to_string()
                .contains("conflicting aft archived recovered-history segment already published for the same covered range"));
        });

        let stored = state
            .get(&aft_archived_recovered_history_segment_key(92, 92))
            .unwrap()
            .expect("stored archived segment bytes");
        let stored: ArchivedRecoveredHistorySegment =
            codec::from_bytes_canonical(&stored).expect("decode stored archived segment");
        assert_eq!(stored, segment);
    }

    fn sample_archived_recovered_restart_page(
        segment: &ArchivedRecoveredHistorySegment,
        parent_block_hash: [u8; 32],
        parent_state_root_hash: [u8; 32],
        state_seed: u8,
    ) -> ArchivedRecoveredRestartPage {
        let restart_entry = RecoveredRestartBlockHeaderEntry {
            certified_header: RecoveredCertifiedHeaderEntry {
                header: RecoveredCanonicalHeaderEntry {
                    height: segment.start_height,
                    view: segment.start_height + 10,
                    canonical_block_commitment_hash: [state_seed.wrapping_add(1); 32],
                    parent_block_commitment_hash: parent_block_hash,
                    transactions_root_hash: [state_seed.wrapping_add(2); 32],
                    resulting_state_root_hash: [state_seed.wrapping_add(3); 32],
                    previous_canonical_collapse_commitment_hash: [state_seed.wrapping_add(4); 32],
                },
                certified_parent_quorum_certificate: QuorumCertificate {
                    height: segment.start_height.saturating_sub(1),
                    view: segment.start_height + 9,
                    block_hash: parent_block_hash,
                    ..Default::default()
                },
                certified_parent_resulting_state_root_hash: parent_state_root_hash,
            },
            header: BlockHeader {
                height: segment.start_height,
                view: segment.start_height + 10,
                parent_hash: parent_block_hash,
                parent_state_root: StateRoot(parent_state_root_hash.to_vec()),
                state_root: StateRoot(vec![state_seed.wrapping_add(3); 32]),
                transactions_root: vec![state_seed.wrapping_add(2); 32],
                timestamp: 1_760_000_000 + segment.start_height,
                timestamp_ms: (1_760_000_000 + segment.start_height) * 1_000,
                gas_used: 0,
                validator_set: Vec::new(),
                producer_account_id: AccountId([state_seed.wrapping_add(5); 32]),
                producer_key_suite: SignatureSuite::ED25519,
                producer_pubkey_hash: [state_seed.wrapping_add(6); 32],
                producer_pubkey: Vec::new(),
                oracle_counter: 0,
                oracle_trace_hash: [0u8; 32],
                parent_qc: QuorumCertificate {
                    height: segment.start_height.saturating_sub(1),
                    view: segment.start_height + 9,
                    block_hash: parent_block_hash,
                    ..Default::default()
                },
                previous_canonical_collapse_commitment_hash: [state_seed.wrapping_add(4); 32],
                canonical_collapse_extension_certificate: None,
                publication_frontier: None,
                guardian_certificate: None,
                sealed_finality_proof: None,
                canonical_order_certificate: None,
                timeout_certificate: None,
                signature: Vec::new(),
            },
        };
        build_archived_recovered_restart_page(segment, std::slice::from_ref(&restart_entry))
            .expect("archived recovered restart page")
    }

    fn sample_archived_recovered_history_checkpoint(
        segment: &ArchivedRecoveredHistorySegment,
        page: &ArchivedRecoveredRestartPage,
        previous: Option<&ArchivedRecoveredHistoryCheckpoint>,
    ) -> ArchivedRecoveredHistoryCheckpoint {
        build_archived_recovered_history_checkpoint(segment, page, previous)
            .expect("archived recovered history checkpoint")
    }

    fn sample_archived_recovered_history_retention_receipt(
        checkpoint: &ArchivedRecoveredHistoryCheckpoint,
        profile: &ArchivedRecoveredHistoryProfile,
        validator_sets: &ValidatorSetsV1,
    ) -> ArchivedRecoveredHistoryRetentionReceipt {
        let validator_set_commitment_hash =
            canonical_validator_sets_hash(validator_sets).expect("validator set commitment hash");
        build_archived_recovered_history_retention_receipt(
            checkpoint,
            validator_set_commitment_hash,
            archived_recovered_history_retained_through_height(checkpoint, profile)
                .expect("retained-through height"),
        )
        .expect("archived recovered history retention receipt")
    }

    fn sample_archived_recovered_history_profile() -> ArchivedRecoveredHistoryProfile {
        build_archived_recovered_history_profile(
            1024,
            1,
            0,
            1,
            1,
            ArchivedRecoveredHistoryCheckpointUpdateRule::EveryPublishedSegmentV1,
        )
        .expect("archived recovered-history profile")
    }

    fn sample_archived_recovered_history_profile_activation(
        profile: &ArchivedRecoveredHistoryProfile,
        previous_activation: Option<&ArchivedRecoveredHistoryProfileActivation>,
        activation_end_height: u64,
    ) -> ArchivedRecoveredHistoryProfileActivation {
        build_archived_recovered_history_profile_activation(
            profile,
            previous_activation,
            activation_end_height,
            None,
        )
        .expect("archived recovered-history profile activation")
    }

    fn sample_bootstrap_archived_recovered_history_profile_activation(
        profile: &ArchivedRecoveredHistoryProfile,
    ) -> ArchivedRecoveredHistoryProfileActivation {
        sample_archived_recovered_history_profile_activation(profile, None, 1)
    }

    fn seed_active_archived_recovered_history_profile(
        state: &mut MockState,
    ) -> ArchivedRecoveredHistoryProfile {
        let profile = sample_archived_recovered_history_profile();
        let profile_hash = canonical_archived_recovered_history_profile_hash(&profile)
            .expect("archived recovered-history profile hash");
        let activation = sample_archived_recovered_history_profile_activation(&profile, None, 1);
        let activation_hash =
            canonical_archived_recovered_history_profile_activation_hash(&activation)
                .expect("archived recovered-history profile activation hash");
        state
            .insert(
                AFT_ACTIVE_ARCHIVED_RECOVERED_HISTORY_PROFILE_KEY,
                &codec::to_bytes_canonical(&profile)
                    .expect("encode active archived recovered-history profile"),
            )
            .expect("store active archived recovered-history profile");
        state
            .insert(
                &aft_archived_recovered_history_profile_hash_key(&profile_hash),
                &codec::to_bytes_canonical(&profile)
                    .expect("encode archived recovered-history profile by hash"),
            )
            .expect("store archived recovered-history profile by hash");
        state
            .insert(
                &aft_archived_recovered_history_profile_activation_key(&profile_hash),
                &codec::to_bytes_canonical(&activation)
                    .expect("encode archived recovered-history profile activation"),
            )
            .expect("store archived recovered-history profile activation by hash");
        state
            .insert(
                &aft_archived_recovered_history_profile_activation_height_key(1),
                &codec::to_bytes_canonical(&activation)
                    .expect("encode archived recovered-history profile activation by height"),
            )
            .expect("store archived recovered-history profile activation by height");
        state
            .insert(
                &aft_archived_recovered_history_profile_activation_hash_key(&activation_hash),
                &codec::to_bytes_canonical(&activation)
                    .expect("encode archived recovered-history profile activation by hash"),
            )
            .expect("store archived recovered-history profile activation by hash");
        state
            .insert(
                AFT_LATEST_ARCHIVED_RECOVERED_HISTORY_PROFILE_ACTIVATION_KEY,
                &codec::to_bytes_canonical(&activation)
                    .expect("encode latest archived recovered-history profile activation"),
            )
            .expect("store latest archived recovered-history profile activation");
        profile
    }

    #[test]
    fn archived_recovered_history_profile_activation_persists_active_profile_and_loads_by_hash() {
        let registry = production_registry();
        let mut state = MockState::default();
        let profile = sample_archived_recovered_history_profile();
        let profile_hash = canonical_archived_recovered_history_profile_hash(&profile)
            .expect("archived recovered-history profile hash");
        let activation = sample_archived_recovered_history_profile_activation(&profile, None, 1);

        with_ctx(|ctx| {
            run_async(registry.handle_service_call(
                &mut state,
                "publish_aft_archived_recovered_history_profile@v1",
                &codec::to_bytes_canonical(&profile).unwrap(),
                ctx,
            ))
            .unwrap();
            run_async(registry.handle_service_call(
                &mut state,
                "publish_aft_archived_recovered_history_profile_activation@v1",
                &codec::to_bytes_canonical(&activation).unwrap(),
                ctx,
            ))
            .unwrap();
        });

        assert_eq!(
            GuardianRegistry::load_active_archived_recovered_history_profile(&state).unwrap(),
            Some(profile.clone())
        );
        assert_eq!(
            GuardianRegistry::load_latest_archived_recovered_history_profile_activation(&state)
                .unwrap(),
            Some(activation.clone())
        );
        assert_eq!(
            GuardianRegistry::load_archived_recovered_history_profile_activation(
                &state,
                &profile_hash,
            )
            .unwrap(),
            Some(activation.clone())
        );
        assert_eq!(
            GuardianRegistry::load_archived_recovered_history_profile_by_hash(
                &state,
                &profile_hash,
            )
            .unwrap(),
            Some(profile.clone())
        );
        assert!(state
            .get(AFT_ACTIVE_ARCHIVED_RECOVERED_HISTORY_PROFILE_KEY)
            .unwrap()
            .is_some());
        assert!(state
            .get(&aft_archived_recovered_history_profile_hash_key(
                &profile_hash
            ))
            .unwrap()
            .is_some());
    }

    #[test]
    fn publishing_conflicting_archived_recovered_history_profile_activation_fails_closed() {
        let registry = production_registry();
        let mut state = MockState::default();
        let profile = sample_archived_recovered_history_profile();
        let activation = sample_archived_recovered_history_profile_activation(&profile, None, 1);
        let conflicting_profile = build_archived_recovered_history_profile(
            profile.retention_horizon + 1,
            profile.restart_page_window,
            profile.restart_page_overlap,
            profile.windows_per_segment,
            profile.segments_per_fold,
            profile.checkpoint_update_rule,
        )
        .expect("conflicting archived recovered-history profile");
        let conflicting_activation =
            sample_archived_recovered_history_profile_activation(&conflicting_profile, None, 1);

        with_ctx(|ctx| {
            run_async(registry.handle_service_call(
                &mut state,
                "publish_aft_archived_recovered_history_profile@v1",
                &codec::to_bytes_canonical(&profile).unwrap(),
                ctx,
            ))
            .unwrap();
            let error = run_async(registry.handle_service_call(
                &mut state,
                "publish_aft_archived_recovered_history_profile_activation@v1",
                &codec::to_bytes_canonical(&activation).unwrap(),
                ctx,
            ))
            .expect("bootstrap activation should publish");
            let _ = run_async(registry.handle_service_call(
                &mut state,
                "publish_aft_archived_recovered_history_profile@v1",
                &codec::to_bytes_canonical(&conflicting_profile).unwrap(),
                ctx,
            ))
            .expect("conflicting profile object should persist by hash");
            let error = run_async(registry.handle_service_call(
                &mut state,
                "publish_aft_archived_recovered_history_profile_activation@v1",
                &codec::to_bytes_canonical(&conflicting_activation).unwrap(),
                ctx,
            ))
            .expect_err("conflicting archived recovered-history profile activation must fail");
            assert!(error
                .to_string()
                .contains("conflicting aft archived recovered-history profile activation already published for the same activation end height"));
        });
    }

    #[test]
    fn archived_recovered_history_segment_page_by_hash_follows_previous_links() {
        let registry = production_registry();
        let mut state = MockState::default();
        let _profile = seed_active_archived_recovered_history_profile(&mut state);
        let (_, _, _, recovered_a) = sample_recovered_publication_bundle_fixture(100, 0x51);
        let (_, _, _, recovered_b) = sample_recovered_publication_bundle_fixture(101, 0x52);
        let (_, _, _, recovered_c) = sample_recovered_publication_bundle_fixture(102, 0x53);

        let segment_a = build_archived_recovered_history_segment(
            std::slice::from_ref(&recovered_a),
            None,
            None,
            &sample_archived_recovered_history_profile(),
            &sample_bootstrap_archived_recovered_history_profile_activation(
                &sample_archived_recovered_history_profile(),
            ),
        )
        .expect("segment a");
        let segment_b = build_archived_recovered_history_segment(
            std::slice::from_ref(&recovered_b),
            Some(&segment_a),
            None,
            &sample_archived_recovered_history_profile(),
            &sample_bootstrap_archived_recovered_history_profile_activation(
                &sample_archived_recovered_history_profile(),
            ),
        )
        .expect("segment b");
        let segment_c = build_archived_recovered_history_segment(
            std::slice::from_ref(&recovered_c),
            Some(&segment_b),
            None,
            &sample_archived_recovered_history_profile(),
            &sample_bootstrap_archived_recovered_history_profile_activation(
                &sample_archived_recovered_history_profile(),
            ),
        )
        .expect("segment c");
        let segment_c_hash =
            canonical_archived_recovered_history_segment_hash(&segment_c).expect("segment c hash");

        with_ctx(|ctx| {
            for segment in [&segment_a, &segment_b, &segment_c] {
                run_async(registry.handle_service_call(
                    &mut state,
                    "publish_aft_archived_recovered_history_segment@v1",
                    &codec::to_bytes_canonical(segment).unwrap(),
                    ctx,
                ))
                .unwrap();
            }
        });

        assert_eq!(
            GuardianRegistry::load_archived_recovered_history_segment_page(
                &state,
                &segment_c_hash,
                2,
            )
            .unwrap(),
            vec![segment_b.clone(), segment_c.clone()]
        );
        assert_eq!(
            GuardianRegistry::load_archived_recovered_history_segment_page(
                &state,
                &segment_c_hash,
                3,
            )
            .unwrap(),
            vec![segment_a, segment_b, segment_c]
        );
    }

    #[test]
    fn archived_recovered_history_segment_page_by_hash_rejects_missing_predecessor() {
        let registry = production_registry();
        let mut state = MockState::default();
        let _profile = seed_active_archived_recovered_history_profile(&mut state);
        let (_, _, _, recovered) = sample_recovered_publication_bundle_fixture(103, 0x61);
        let mut segment = build_archived_recovered_history_segment(
            std::slice::from_ref(&recovered),
            None,
            None,
            &sample_archived_recovered_history_profile(),
            &sample_bootstrap_archived_recovered_history_profile_activation(
                &sample_archived_recovered_history_profile(),
            ),
        )
        .expect("archived segment");
        segment.previous_archived_segment_hash = [0xCD; 32];
        let segment_hash =
            canonical_archived_recovered_history_segment_hash(&segment).expect("segment hash");

        with_ctx(|ctx| {
            run_async(registry.handle_service_call(
                &mut state,
                "publish_aft_archived_recovered_history_segment@v1",
                &codec::to_bytes_canonical(&segment).unwrap(),
                ctx,
            ))
            .unwrap();
        });

        let error = GuardianRegistry::load_archived_recovered_history_segment_page(
            &state,
            &segment_hash,
            2,
        )
        .expect_err("missing predecessor should fail closed");
        assert!(error
            .to_string()
            .contains("predecessor hash is missing from state"));
    }

    #[test]
    fn archived_recovered_history_segment_page_by_hash_rejects_invalid_overlap_anchor() {
        let registry = production_registry();
        let mut state = MockState::default();
        let _profile = seed_active_archived_recovered_history_profile(&mut state);
        let (_, _, _, recovered_a) = sample_recovered_publication_bundle_fixture(104, 0x71);
        let (_, _, _, recovered_b) = sample_recovered_publication_bundle_fixture(105, 0x72);

        let previous = build_archived_recovered_history_segment(
            std::slice::from_ref(&recovered_a),
            None,
            None,
            &sample_archived_recovered_history_profile(),
            &sample_bootstrap_archived_recovered_history_profile_activation(
                &sample_archived_recovered_history_profile(),
            ),
        )
        .expect("previous segment");
        let mut current = build_archived_recovered_history_segment(
            std::slice::from_ref(&recovered_b),
            Some(&previous),
            None,
            &sample_archived_recovered_history_profile(),
            &sample_bootstrap_archived_recovered_history_profile_activation(
                &sample_archived_recovered_history_profile(),
            ),
        )
        .expect("current segment");
        current.overlap_start_height = current.start_height;
        current.overlap_end_height = current.end_height;
        current.overlap_root_hash = current.segment_root_hash;
        let current_hash =
            canonical_archived_recovered_history_segment_hash(&current).expect("current hash");

        with_ctx(|ctx| {
            run_async(registry.handle_service_call(
                &mut state,
                "publish_aft_archived_recovered_history_segment@v1",
                &codec::to_bytes_canonical(&previous).unwrap(),
                ctx,
            ))
            .unwrap();
            run_async(registry.handle_service_call(
                &mut state,
                "publish_aft_archived_recovered_history_segment@v1",
                &codec::to_bytes_canonical(&current).unwrap(),
                ctx,
            ))
            .unwrap();
        });

        let error = GuardianRegistry::load_archived_recovered_history_segment_page(
            &state,
            &current_hash,
            2,
        )
        .expect_err("invalid overlap anchor should fail closed");
        assert!(error
            .to_string()
            .contains("does not cover the declared overlap anchor"));
    }

    #[test]
    fn archived_recovered_restart_pages_follow_segment_hash_chain() {
        let registry = production_registry();
        let mut state = MockState::default();
        let _profile = seed_active_archived_recovered_history_profile(&mut state);
        let (_, _, _, recovered_a) = sample_recovered_publication_bundle_fixture(106, 0x81);
        let (_, _, _, recovered_b) = sample_recovered_publication_bundle_fixture(107, 0x82);
        let segment_a = build_archived_recovered_history_segment(
            std::slice::from_ref(&recovered_a),
            None,
            None,
            &sample_archived_recovered_history_profile(),
            &sample_bootstrap_archived_recovered_history_profile_activation(
                &sample_archived_recovered_history_profile(),
            ),
        )
        .expect("segment a");
        let segment_b = build_archived_recovered_history_segment(
            std::slice::from_ref(&recovered_b),
            Some(&segment_a),
            None,
            &sample_archived_recovered_history_profile(),
            &sample_bootstrap_archived_recovered_history_profile_activation(
                &sample_archived_recovered_history_profile(),
            ),
        )
        .expect("segment b");
        let page_a =
            sample_archived_recovered_restart_page(&segment_a, [0x11; 32], [0x12; 32], 0x13);
        let page_b = sample_archived_recovered_restart_page(
            &segment_b,
            page_a.restart_headers[0]
                .certified_header
                .header
                .canonical_block_commitment_hash,
            page_a.restart_headers[0]
                .certified_header
                .header
                .resulting_state_root_hash,
            0x21,
        );
        let segment_b_hash =
            canonical_archived_recovered_history_segment_hash(&segment_b).expect("segment b hash");

        with_ctx(|ctx| {
            for segment in [&segment_a, &segment_b] {
                run_async(registry.handle_service_call(
                    &mut state,
                    "publish_aft_archived_recovered_history_segment@v1",
                    &codec::to_bytes_canonical(segment).unwrap(),
                    ctx,
                ))
                .unwrap();
            }
            for page in [&page_a, &page_b] {
                run_async(registry.handle_service_call(
                    &mut state,
                    "publish_aft_archived_recovered_restart_page@v1",
                    &codec::to_bytes_canonical(page).unwrap(),
                    ctx,
                ))
                .unwrap();
            }
        });

        assert_eq!(
            GuardianRegistry::load_archived_recovered_restart_page(&state, &page_b.segment_hash)
                .unwrap(),
            Some(page_b.clone())
        );
        assert_eq!(
            GuardianRegistry::load_archived_recovered_restart_page_for_range(
                &state,
                segment_b.start_height,
                segment_b.end_height,
            )
            .unwrap(),
            Some(page_b.clone())
        );
        assert_eq!(
            GuardianRegistry::load_archived_recovered_restart_page_chain(
                &state,
                &segment_b_hash,
                2
            )
            .unwrap(),
            vec![page_a, page_b]
        );
        assert!(state
            .get(&aft_archived_recovered_restart_page_key(&segment_b_hash))
            .unwrap()
            .is_some());
    }

    #[test]
    fn archived_recovered_history_checkpoints_persist_latest_tip_and_load_by_hash() {
        let registry = production_registry();
        let mut state = MockState::default();
        let _profile = seed_active_archived_recovered_history_profile(&mut state);
        let (_, _, _, recovered_a) = sample_recovered_publication_bundle_fixture(108, 0x91);
        let (_, _, _, recovered_b) = sample_recovered_publication_bundle_fixture(109, 0x92);
        let segment_a = build_archived_recovered_history_segment(
            std::slice::from_ref(&recovered_a),
            None,
            None,
            &sample_archived_recovered_history_profile(),
            &sample_bootstrap_archived_recovered_history_profile_activation(
                &sample_archived_recovered_history_profile(),
            ),
        )
        .expect("segment a");
        let segment_b = build_archived_recovered_history_segment(
            std::slice::from_ref(&recovered_b),
            Some(&segment_a),
            None,
            &sample_archived_recovered_history_profile(),
            &sample_bootstrap_archived_recovered_history_profile_activation(
                &sample_archived_recovered_history_profile(),
            ),
        )
        .expect("segment b");
        let page_a =
            sample_archived_recovered_restart_page(&segment_a, [0x31; 32], [0x32; 32], 0x33);
        let page_b = sample_archived_recovered_restart_page(
            &segment_b,
            page_a.restart_headers[0]
                .certified_header
                .header
                .canonical_block_commitment_hash,
            page_a.restart_headers[0]
                .certified_header
                .header
                .resulting_state_root_hash,
            0x34,
        );
        let checkpoint_a = sample_archived_recovered_history_checkpoint(&segment_a, &page_a, None);
        let checkpoint_b =
            sample_archived_recovered_history_checkpoint(&segment_b, &page_b, Some(&checkpoint_a));
        let checkpoint_b_hash = canonical_archived_recovered_history_checkpoint_hash(&checkpoint_b)
            .expect("checkpoint b hash");

        with_ctx(|ctx| {
            for segment in [&segment_a, &segment_b] {
                run_async(registry.handle_service_call(
                    &mut state,
                    "publish_aft_archived_recovered_history_segment@v1",
                    &codec::to_bytes_canonical(segment).unwrap(),
                    ctx,
                ))
                .unwrap();
            }
            for page in [&page_a, &page_b] {
                run_async(registry.handle_service_call(
                    &mut state,
                    "publish_aft_archived_recovered_restart_page@v1",
                    &codec::to_bytes_canonical(page).unwrap(),
                    ctx,
                ))
                .unwrap();
            }
            for checkpoint in [&checkpoint_a, &checkpoint_b] {
                run_async(registry.handle_service_call(
                    &mut state,
                    "publish_aft_archived_recovered_history_checkpoint@v1",
                    &codec::to_bytes_canonical(checkpoint).unwrap(),
                    ctx,
                ))
                .unwrap();
            }
        });

        assert_eq!(
            GuardianRegistry::load_archived_recovered_history_checkpoint(
                &state,
                checkpoint_b.covered_start_height,
                checkpoint_b.covered_end_height,
            )
            .unwrap(),
            Some(checkpoint_b.clone())
        );
        assert_eq!(
            GuardianRegistry::load_archived_recovered_history_checkpoint_by_hash(
                &state,
                &checkpoint_b_hash,
            )
            .unwrap(),
            Some(checkpoint_b.clone())
        );
        assert_eq!(
            GuardianRegistry::load_latest_archived_recovered_history_checkpoint(&state).unwrap(),
            Some(checkpoint_b.clone())
        );
        assert!(state
            .get(AFT_LATEST_ARCHIVED_RECOVERED_HISTORY_CHECKPOINT_KEY)
            .unwrap()
            .is_some());
        assert!(state
            .get(&aft_archived_recovered_history_checkpoint_hash_key(
                &checkpoint_b_hash,
            ))
            .unwrap()
            .is_some());
    }

    #[test]
    fn publishing_conflicting_archived_recovered_history_checkpoint_for_same_range_fails_closed() {
        let registry = production_registry();
        let mut state = MockState::default();
        let _profile = seed_active_archived_recovered_history_profile(&mut state);
        let (_, _, _, recovered_prev_alt) = sample_recovered_publication_bundle_fixture(205, 0xA1);
        let (_, _, _, recovered_prev) = sample_recovered_publication_bundle_fixture(206, 0xA2);
        let (_, _, _, recovered_current) = sample_recovered_publication_bundle_fixture(207, 0xA3);
        let segment_prev_alt = build_archived_recovered_history_segment(
            std::slice::from_ref(&recovered_prev_alt),
            None,
            None,
            &sample_archived_recovered_history_profile(),
            &sample_bootstrap_archived_recovered_history_profile_activation(
                &sample_archived_recovered_history_profile(),
            ),
        )
        .expect("previous alt segment");
        let segment_prev = build_archived_recovered_history_segment(
            std::slice::from_ref(&recovered_prev),
            Some(&segment_prev_alt),
            None,
            &sample_archived_recovered_history_profile(),
            &sample_bootstrap_archived_recovered_history_profile_activation(
                &sample_archived_recovered_history_profile(),
            ),
        )
        .expect("previous segment");
        let segment_current = build_archived_recovered_history_segment(
            std::slice::from_ref(&recovered_current),
            Some(&segment_prev),
            None,
            &sample_archived_recovered_history_profile(),
            &sample_bootstrap_archived_recovered_history_profile_activation(
                &sample_archived_recovered_history_profile(),
            ),
        )
        .expect("current segment");
        let page_prev_alt =
            sample_archived_recovered_restart_page(&segment_prev_alt, [0x41; 32], [0x42; 32], 0x43);
        let page_prev = sample_archived_recovered_restart_page(
            &segment_prev,
            page_prev_alt.restart_headers[0]
                .certified_header
                .header
                .canonical_block_commitment_hash,
            page_prev_alt.restart_headers[0]
                .certified_header
                .header
                .resulting_state_root_hash,
            0x44,
        );
        let page_current = sample_archived_recovered_restart_page(
            &segment_current,
            page_prev.restart_headers[0]
                .certified_header
                .header
                .canonical_block_commitment_hash,
            page_prev.restart_headers[0]
                .certified_header
                .header
                .resulting_state_root_hash,
            0x45,
        );
        let checkpoint_prev_alt =
            sample_archived_recovered_history_checkpoint(&segment_prev_alt, &page_prev_alt, None);
        let checkpoint_prev = sample_archived_recovered_history_checkpoint(
            &segment_prev,
            &page_prev,
            Some(&checkpoint_prev_alt),
        );
        let checkpoint_current = sample_archived_recovered_history_checkpoint(
            &segment_current,
            &page_current,
            Some(&checkpoint_prev),
        );
        let conflicting_checkpoint_current = sample_archived_recovered_history_checkpoint(
            &segment_current,
            &page_current,
            Some(&checkpoint_prev_alt),
        );

        with_ctx(|ctx| {
            for segment in [&segment_prev_alt, &segment_prev, &segment_current] {
                run_async(registry.handle_service_call(
                    &mut state,
                    "publish_aft_archived_recovered_history_segment@v1",
                    &codec::to_bytes_canonical(segment).unwrap(),
                    ctx,
                ))
                .unwrap();
            }
            for page in [&page_prev_alt, &page_prev, &page_current] {
                run_async(registry.handle_service_call(
                    &mut state,
                    "publish_aft_archived_recovered_restart_page@v1",
                    &codec::to_bytes_canonical(page).unwrap(),
                    ctx,
                ))
                .unwrap();
            }
            for checkpoint in [&checkpoint_prev_alt, &checkpoint_prev, &checkpoint_current] {
                run_async(registry.handle_service_call(
                    &mut state,
                    "publish_aft_archived_recovered_history_checkpoint@v1",
                    &codec::to_bytes_canonical(checkpoint).unwrap(),
                    ctx,
                ))
                .unwrap();
            }
            let error = run_async(registry.handle_service_call(
                &mut state,
                "publish_aft_archived_recovered_history_checkpoint@v1",
                &codec::to_bytes_canonical(&conflicting_checkpoint_current).unwrap(),
                ctx,
            ))
            .expect_err("conflicting archived checkpoint on the same covered range should fail");
            assert!(error
                .to_string()
                .contains("conflicting aft archived recovered-history checkpoint already published for the same covered range"));
        });
    }

    #[test]
    fn archived_recovered_history_retention_receipts_persist_by_checkpoint_hash() {
        let registry = production_registry();
        let mut state = MockState::default();
        let profile = seed_active_archived_recovered_history_profile(&mut state);
        let validator_sets = validator_sets(&[(18, 1), (145, 1), (19, 1)]);
        state
            .insert(
                VALIDATOR_SET_KEY,
                &write_validator_sets(&validator_sets).unwrap(),
            )
            .unwrap();
        let validator_sets = read_validator_sets(&state.get(VALIDATOR_SET_KEY).unwrap().unwrap())
            .expect("decode persisted validator set");

        let (_, _, _, recovered) = sample_recovered_publication_bundle_fixture(208, 0xB1);
        let segment = build_archived_recovered_history_segment(
            std::slice::from_ref(&recovered),
            None,
            None,
            &sample_archived_recovered_history_profile(),
            &sample_bootstrap_archived_recovered_history_profile_activation(
                &sample_archived_recovered_history_profile(),
            ),
        )
        .expect("segment");
        let page = sample_archived_recovered_restart_page(&segment, [0x61; 32], [0x62; 32], 0x63);
        let checkpoint = sample_archived_recovered_history_checkpoint(&segment, &page, None);
        let checkpoint_hash =
            canonical_archived_recovered_history_checkpoint_hash(&checkpoint).expect("hash");
        let receipt = sample_archived_recovered_history_retention_receipt(
            &checkpoint,
            &profile,
            &validator_sets,
        );

        with_ctx(|ctx| {
            run_async(registry.handle_service_call(
                &mut state,
                "publish_aft_archived_recovered_history_segment@v1",
                &codec::to_bytes_canonical(&segment).unwrap(),
                ctx,
            ))
            .unwrap();
            run_async(registry.handle_service_call(
                &mut state,
                "publish_aft_archived_recovered_restart_page@v1",
                &codec::to_bytes_canonical(&page).unwrap(),
                ctx,
            ))
            .unwrap();
            run_async(registry.handle_service_call(
                &mut state,
                "publish_aft_archived_recovered_history_checkpoint@v1",
                &codec::to_bytes_canonical(&checkpoint).unwrap(),
                ctx,
            ))
            .unwrap();
            run_async(registry.handle_service_call(
                &mut state,
                "publish_aft_archived_recovered_history_retention_receipt@v1",
                &codec::to_bytes_canonical(&receipt).unwrap(),
                ctx,
            ))
            .unwrap();
        });

        assert_eq!(
            GuardianRegistry::load_archived_recovered_history_retention_receipt(
                &state,
                &checkpoint_hash,
            )
            .unwrap(),
            Some(receipt.clone())
        );
        assert!(state
            .get(&aft_archived_recovered_history_retention_receipt_key(
                &checkpoint_hash,
            ))
            .unwrap()
            .is_some());
        assert_ne!(
            canonical_archived_recovered_history_retention_receipt_hash(&receipt)
                .expect("receipt hash"),
            [0u8; 32]
        );
    }

    #[test]
    fn aft_recovered_state_surface_loads_ordinary_historical_continuation_from_canonical_tip() {
        let registry = production_registry();
        let mut state = MockState::default();
        let profile = seed_active_archived_recovered_history_profile(&mut state);
        let activation = sample_bootstrap_archived_recovered_history_profile_activation(&profile);
        let validator_sets = validator_sets(&[(21, 1), (22, 1), (23, 1)]);
        state
            .insert(
                VALIDATOR_SET_KEY,
                &write_validator_sets(&validator_sets).unwrap(),
            )
            .unwrap();
        let validator_sets = read_validator_sets(&state.get(VALIDATOR_SET_KEY).unwrap().unwrap())
            .expect("decode persisted validator set");

        let (_, _, _, recovered) = sample_recovered_publication_bundle_fixture(144, 0xC1);
        let segment = build_archived_recovered_history_segment(
            std::slice::from_ref(&recovered),
            None,
            None,
            &profile,
            &activation,
        )
        .expect("segment");
        let page = sample_archived_recovered_restart_page(&segment, [0x71; 32], [0x72; 32], 0x73);
        let checkpoint = sample_archived_recovered_history_checkpoint(&segment, &page, None);
        let checkpoint_hash =
            canonical_archived_recovered_history_checkpoint_hash(&checkpoint).expect("hash");
        let receipt = sample_archived_recovered_history_retention_receipt(
            &checkpoint,
            &profile,
            &validator_sets,
        );
        let receipt_hash =
            canonical_archived_recovered_history_retention_receipt_hash(&receipt).expect("hash");
        let activation_hash =
            canonical_archived_recovered_history_profile_activation_hash(&activation)
                .expect("activation hash");

        with_ctx(|ctx| {
            run_async(registry.handle_service_call(
                &mut state,
                "publish_aft_archived_recovered_history_segment@v1",
                &codec::to_bytes_canonical(&segment).unwrap(),
                ctx,
            ))
            .unwrap();
            run_async(registry.handle_service_call(
                &mut state,
                "publish_aft_archived_recovered_restart_page@v1",
                &codec::to_bytes_canonical(&page).unwrap(),
                ctx,
            ))
            .unwrap();
            run_async(registry.handle_service_call(
                &mut state,
                "publish_aft_archived_recovered_history_checkpoint@v1",
                &codec::to_bytes_canonical(&checkpoint).unwrap(),
                ctx,
            ))
            .unwrap();
            run_async(registry.handle_service_call(
                &mut state,
                "publish_aft_archived_recovered_history_retention_receipt@v1",
                &codec::to_bytes_canonical(&receipt).unwrap(),
                ctx,
            ))
            .unwrap();
        });

        let mut collapse = CanonicalCollapseObject {
            height: checkpoint.covered_end_height,
            ..Default::default()
        };
        set_canonical_collapse_archived_recovered_history_anchor(
            &mut collapse,
            checkpoint_hash,
            activation_hash,
            receipt_hash,
        )
        .expect("set historical continuation anchor");
        state
            .insert(
                &aft_canonical_collapse_object_key(collapse.height),
                &codec::to_bytes_canonical(&collapse).unwrap(),
            )
            .unwrap();

        let continuation = GuardianRegistry::load_aft_historical_continuation_surface_for_height(
            &state,
            collapse.height,
        )
        .expect("load ordinary historical continuation")
        .expect("historical continuation present");
        assert_eq!(continuation.anchor.checkpoint_hash, checkpoint_hash);
        assert_eq!(continuation.anchor.profile_activation_hash, activation_hash);
        assert_eq!(continuation.anchor.retention_receipt_hash, receipt_hash);
        assert_eq!(continuation.checkpoint, checkpoint);
        assert_eq!(continuation.profile_activation, activation);
        assert_eq!(continuation.retention_receipt, receipt);
    }

    #[test]
    fn publishing_conflicting_archived_recovered_history_retention_receipt_fails_closed() {
        let registry = production_registry();
        let mut state = MockState::default();
        let profile = seed_active_archived_recovered_history_profile(&mut state);
        let validator_sets = validator_sets(&[(7, 1), (11, 1), (12, 1)]);
        state
            .insert(
                VALIDATOR_SET_KEY,
                &write_validator_sets(&validator_sets).unwrap(),
            )
            .unwrap();
        let validator_sets = read_validator_sets(&state.get(VALIDATOR_SET_KEY).unwrap().unwrap())
            .expect("decode persisted validator set");

        let (_, _, _, recovered) = sample_recovered_publication_bundle_fixture(209, 0xB2);
        let segment = build_archived_recovered_history_segment(
            std::slice::from_ref(&recovered),
            None,
            None,
            &sample_archived_recovered_history_profile(),
            &sample_bootstrap_archived_recovered_history_profile_activation(
                &sample_archived_recovered_history_profile(),
            ),
        )
        .expect("segment");
        let page = sample_archived_recovered_restart_page(&segment, [0x71; 32], [0x72; 32], 0x73);
        let checkpoint = sample_archived_recovered_history_checkpoint(&segment, &page, None);
        let receipt = sample_archived_recovered_history_retention_receipt(
            &checkpoint,
            &profile,
            &validator_sets,
        );
        let conflicting_receipt = ArchivedRecoveredHistoryRetentionReceipt {
            retained_through_height: receipt.retained_through_height + 1,
            ..receipt.clone()
        };

        with_ctx(|ctx| {
            run_async(registry.handle_service_call(
                &mut state,
                "publish_aft_archived_recovered_history_segment@v1",
                &codec::to_bytes_canonical(&segment).unwrap(),
                ctx,
            ))
            .unwrap();
            run_async(registry.handle_service_call(
                &mut state,
                "publish_aft_archived_recovered_restart_page@v1",
                &codec::to_bytes_canonical(&page).unwrap(),
                ctx,
            ))
            .unwrap();
            run_async(registry.handle_service_call(
                &mut state,
                "publish_aft_archived_recovered_history_checkpoint@v1",
                &codec::to_bytes_canonical(&checkpoint).unwrap(),
                ctx,
            ))
            .unwrap();
            run_async(registry.handle_service_call(
                &mut state,
                "publish_aft_archived_recovered_history_retention_receipt@v1",
                &codec::to_bytes_canonical(&receipt).unwrap(),
                ctx,
            ))
            .unwrap();
            let error = run_async(registry.handle_service_call(
                &mut state,
                "publish_aft_archived_recovered_history_retention_receipt@v1",
                &codec::to_bytes_canonical(&conflicting_receipt).unwrap(),
                ctx,
            ))
            .expect_err("conflicting retention receipt must fail");
            let error_text = error.to_string();
            assert!(
                error_text.contains(
                    "conflicting aft archived recovered-history retention receipt already published for the same archived checkpoint"
                ) || error_text.contains(
                    "archived recovered-history retention receipt retained-through height"
                )
            );
        });

        let checkpoint_hash = canonical_archived_recovered_history_checkpoint_hash(&checkpoint)
            .expect("archived checkpoint hash");
        assert_eq!(
            GuardianRegistry::load_archived_recovered_history_retention_receipt(
                &state,
                &checkpoint_hash,
            )
            .unwrap(),
            Some(receipt)
        );
    }

    fn recovered_publication_frontier_header(
        payload: &ioi_types::app::RecoverableSlotPayloadV5,
    ) -> BlockHeader {
        BlockHeader {
            height: payload.height,
            view: payload.view,
            parent_hash: payload.parent_block_hash,
            parent_state_root: StateRoot(
                payload
                    .canonical_order_certificate
                    .resulting_state_root_hash
                    .to_vec(),
            ),
            state_root: StateRoot(
                payload
                    .canonical_order_certificate
                    .resulting_state_root_hash
                    .to_vec(),
            ),
            transactions_root: payload
                .canonical_order_certificate
                .ordered_transactions_root_hash
                .to_vec(),
            timestamp: payload
                .canonical_order_certificate
                .bulletin_commitment
                .cutoff_timestamp_ms
                / 1_000,
            timestamp_ms: payload
                .canonical_order_certificate
                .bulletin_commitment
                .cutoff_timestamp_ms,
            gas_used: 0,
            validator_set: Vec::new(),
            producer_account_id: payload.producer_account_id,
            producer_key_suite: SignatureSuite::ED25519,
            producer_pubkey_hash: [0u8; 32],
            producer_pubkey: Vec::new(),
            signature: Vec::new(),
            oracle_counter: 0,
            oracle_trace_hash: [0u8; 32],
            parent_qc: QuorumCertificate::default(),
            previous_canonical_collapse_commitment_hash: [0u8; 32],
            canonical_collapse_extension_certificate: None,
            publication_frontier: None,
            guardian_certificate: None,
            sealed_finality_proof: None,
            canonical_order_certificate: Some(payload.canonical_order_certificate.clone()),
            timeout_certificate: None,
        }
    }

    fn validator_sets(validators: &[(u8, u128)]) -> ValidatorSetsV1 {
        let entries = validators
            .iter()
            .map(|(account, weight)| validator(*account, *weight))
            .collect::<Vec<_>>();
        ValidatorSetsV1 {
            current: ValidatorSetV1 {
                effective_from_height: 1,
                total_weight: entries.iter().map(|validator| validator.weight).sum(),
                validators: entries,
            },
            next: None,
        }
    }

    fn member(
        member_id: &str,
        provider: &str,
        region: &str,
        host_class: &str,
        key_authority_kind: ioi_types::app::KeyAuthorityKind,
    ) -> GuardianCommitteeMember {
        GuardianCommitteeMember {
            member_id: member_id.to_string(),
            signature_suite: SignatureSuite::BLS12_381,
            public_key: vec![1, 2, 3, member_id.len() as u8],
            endpoint: Some(format!("https://{}.example", member_id)),
            provider: Some(provider.to_string()),
            region: Some(region.to_string()),
            host_class: Some(host_class.to_string()),
            key_authority_kind: Some(key_authority_kind),
        }
    }

    #[test]
    fn rejects_unsafe_odd_sized_guardian_committee_under_production_policy() {
        let registry = production_registry();
        let manifest = GuardianCommitteeManifest {
            validator_account_id: AccountId([1u8; 32]),
            epoch: 7,
            threshold: 3,
            members: vec![
                member(
                    "a",
                    "aws",
                    "us-east-1",
                    "x86",
                    ioi_types::app::KeyAuthorityKind::CloudKms,
                ),
                member(
                    "b",
                    "gcp",
                    "us-west-1",
                    "arm",
                    ioi_types::app::KeyAuthorityKind::Tpm2,
                ),
                member(
                    "c",
                    "azure",
                    "eu-west-1",
                    "metal",
                    ioi_types::app::KeyAuthorityKind::Pkcs11,
                ),
                member(
                    "d",
                    "aws",
                    "eu-central-1",
                    "arm64",
                    ioi_types::app::KeyAuthorityKind::CloudKms,
                ),
                member(
                    "e",
                    "gcp",
                    "ap-southeast-1",
                    "x86_64",
                    ioi_types::app::KeyAuthorityKind::Tpm2,
                ),
            ],
            measurement_profile_root: [1u8; 32],
            policy_hash: [2u8; 32],
            transparency_log_id: "guardian-log".into(),
        };

        let mut state = MockState::default();
        with_ctx(|ctx| {
            let err = run_async(registry.handle_service_call(
                &mut state,
                "register_guardian_committee@v1",
                &codec::to_bytes_canonical(&manifest).unwrap(),
                ctx,
            ))
            .unwrap_err();
            assert!(err.to_string().contains("even-sized"));
        });
    }

    #[test]
    fn registers_guardian_transparency_log_descriptor() {
        let registry = GuardianRegistry::new(Default::default());
        let descriptor = GuardianTransparencyLogDescriptor {
            log_id: "guardian-log".into(),
            signature_suite: SignatureSuite::ED25519,
            public_key: vec![1, 2, 3],
        };
        let mut state = MockState::default();

        with_ctx(|ctx| {
            run_async(registry.handle_service_call(
                &mut state,
                "register_guardian_transparency_log@v1",
                &codec::to_bytes_canonical(&descriptor).unwrap(),
                ctx,
            ))
            .unwrap();
        });

        let stored = state
            .get(&guardian_registry_log_key(&descriptor.log_id))
            .unwrap()
            .expect("log descriptor stored");
        let restored: GuardianTransparencyLogDescriptor =
            codec::from_bytes_canonical(&stored).unwrap();
        assert_eq!(restored, descriptor);
    }

    #[test]
    fn registering_witness_committee_updates_active_set_and_seed() {
        let registry = GuardianRegistry::new(GuardianRegistryParams {
            enabled: true,
            minimum_committee_size: 1,
            minimum_witness_committee_size: 1,
            minimum_provider_diversity: 1,
            minimum_region_diversity: 1,
            minimum_host_class_diversity: 1,
            minimum_backend_diversity: 1,
            require_even_committee_sizes: false,
            require_checkpoint_anchoring: true,
            max_checkpoint_staleness_ms: 120_000,
            max_committee_outage_members: 0,
            asymptote_required_witness_strata: vec!["stratum-a".into()],
            asymptote_escalation_witness_strata: vec!["stratum-a".into()],
            asymptote_high_risk_effect_tier: ioi_types::app::FinalityTier::SealedFinal,
            apply_accountable_membership_updates: true,
        });
        let manifest = GuardianWitnessCommitteeManifest {
            committee_id: "witness-a".into(),
            stratum_id: "stratum-a".into(),
            epoch: 11,
            threshold: 1,
            members: vec![member(
                "w1",
                "aws",
                "us-east-1",
                "arm",
                ioi_types::app::KeyAuthorityKind::CloudKms,
            )],
            policy_hash: [3u8; 32],
            transparency_log_id: "witness-log".into(),
        };
        let seed = GuardianWitnessEpochSeed {
            epoch: 11,
            seed: [9u8; 32],
            checkpoint_interval_blocks: 3,
            max_reassignment_depth: 2,
        };

        let mut state = MockState::default();
        with_ctx(|ctx| {
            run_async(registry.handle_service_call(
                &mut state,
                "register_guardian_witness_committee@v1",
                &codec::to_bytes_canonical(&manifest).unwrap(),
                ctx,
            ))
            .unwrap();
            run_async(registry.handle_service_call(
                &mut state,
                "publish_witness_epoch_seed@v1",
                &codec::to_bytes_canonical(&seed).unwrap(),
                ctx,
            ))
            .unwrap();
        });

        let active_set_bytes = state
            .get(&guardian_registry_witness_set_key(11))
            .expect("active set lookup")
            .expect("active set stored");
        let active_set: GuardianWitnessSet =
            codec::from_bytes_canonical(&active_set_bytes).unwrap();
        assert_eq!(active_set.epoch, 11);
        assert_eq!(active_set.manifest_hashes.len(), 1);
        assert_eq!(active_set.checkpoint_interval_blocks, 3);

        let seed_bytes = state
            .get(&guardian_registry_witness_seed_key(11))
            .expect("seed lookup")
            .expect("seed stored");
        let stored_seed: GuardianWitnessEpochSeed =
            codec::from_bytes_canonical(&seed_bytes).unwrap();
        assert_eq!(stored_seed.seed, [9u8; 32]);
        assert_eq!(stored_seed.max_reassignment_depth, 2);
    }

    #[test]
    fn registering_effect_verifier_and_recording_sealed_effect_persists_both_keys() {
        let registry = production_registry();
        let verifier = EffectProofVerifierDescriptor {
            verifier_id: "aft-http-egress-hash-binding-v1".into(),
            effect_class: SealedEffectClass::HttpEgress,
            proof_system: EffectProofSystem::HashBindingV1,
            verifying_key_hash: [21u8; 32],
            enabled: true,
        };
        let record = SealedEffectRecord {
            nullifier: [22u8; 32],
            intent_hash: [23u8; 32],
            epoch: 7,
            effect_class: SealedEffectClass::HttpEgress,
            verifier_id: verifier.verifier_id.clone(),
            seal_hash: [24u8; 32],
        };

        let mut state = MockState::default();
        with_ctx(|ctx| {
            run_async(registry.handle_service_call(
                &mut state,
                "register_effect_proof_verifier@v1",
                &codec::to_bytes_canonical(&verifier).unwrap(),
                ctx,
            ))
            .unwrap();
            run_async(registry.handle_service_call(
                &mut state,
                "record_sealed_effect@v1",
                &codec::to_bytes_canonical(&record).unwrap(),
                ctx,
            ))
            .unwrap();
        });

        let stored_verifier = state
            .get(&guardian_registry_effect_verifier_key(
                &verifier.verifier_id,
            ))
            .unwrap()
            .expect("effect verifier stored");
        let restored_verifier: EffectProofVerifierDescriptor =
            codec::from_bytes_canonical(&stored_verifier).unwrap();
        assert_eq!(restored_verifier, verifier);

        let nullifier_record = state
            .get(&guardian_registry_effect_nullifier_key(&record.nullifier))
            .unwrap()
            .expect("sealed effect nullifier record stored");
        let sealed_effect_record = state
            .get(&guardian_registry_sealed_effect_key(&record.intent_hash))
            .unwrap()
            .expect("sealed effect record stored");
        let restored_nullifier_record: SealedEffectRecord =
            codec::from_bytes_canonical(&nullifier_record).unwrap();
        let restored_effect_record: SealedEffectRecord =
            codec::from_bytes_canonical(&sealed_effect_record).unwrap();
        assert_eq!(restored_nullifier_record, record);
        assert_eq!(restored_effect_record, record);
    }

    #[test]
    fn publishing_aft_canonical_order_artifact_bundle_persists_registry_state() {
        let registry = production_registry();
        let base_header = ioi_types::app::BlockHeader {
            height: 9,
            view: 2,
            parent_hash: [11u8; 32],
            parent_state_root: StateRoot(vec![1u8; 32]),
            state_root: StateRoot(vec![2u8; 32]),
            transactions_root: Vec::new(),
            timestamp: 1_760_000_111,
            timestamp_ms: 1_760_000_111_000,
            gas_used: 0,
            validator_set: Vec::new(),
            producer_account_id: AccountId([12u8; 32]),
            producer_key_suite: SignatureSuite::ED25519,
            producer_pubkey_hash: [13u8; 32],
            producer_pubkey: Vec::new(),
            signature: Vec::new(),
            oracle_counter: 0,
            oracle_trace_hash: [0u8; 32],
            parent_qc: QuorumCertificate::default(),
            previous_canonical_collapse_commitment_hash: [0u8; 32],
            canonical_collapse_extension_certificate: None,
            publication_frontier: None,
            guardian_certificate: None,
            sealed_finality_proof: None,
            canonical_order_certificate: None,
            timeout_certificate: None,
        };
        let tx_one = ChainTransaction::System(Box::new(SystemTransaction {
            header: SignHeader {
                account_id: AccountId([31u8; 32]),
                nonce: 1,
                chain_id: ChainId(1),
                tx_version: 1,
                session_auth: None,
            },
            payload: SystemPayload::CallService {
                service_id: "guardian_registry".into(),
                method: "publish_aft_bulletin_commitment@v1".into(),
                params: vec![1],
            },
            signature_proof: SignatureProof::default(),
        }));
        let tx_two = ChainTransaction::System(Box::new(SystemTransaction {
            header: SignHeader {
                account_id: AccountId([32u8; 32]),
                nonce: 1,
                chain_id: ChainId(1),
                tx_version: 1,
                session_auth: None,
            },
            payload: SystemPayload::CallService {
                service_id: "guardian_registry".into(),
                method: "publish_aft_canonical_order_artifact_bundle@v1".into(),
                params: vec![2],
            },
            signature_proof: SignatureProof::default(),
        }));

        let ordered_transactions =
            canonicalize_transactions_for_header(&base_header, &[tx_one, tx_two]).unwrap();
        let tx_hashes: Vec<[u8; 32]> = ordered_transactions
            .iter()
            .map(|tx| tx.hash().unwrap())
            .collect();
        let mut header = base_header;
        header.transactions_root = canonical_transaction_root_from_hashes(&tx_hashes).unwrap();
        let mut certificate =
            build_committed_surface_canonical_order_certificate(&header, &ordered_transactions)
                .unwrap();
        let omission = OmissionProof {
            height: header.height,
            offender_account_id: AccountId([41u8; 32]),
            tx_hash: [42u8; 32],
            bulletin_root: certificate.bulletin_commitment.bulletin_root,
            details: "tx omitted from canonical order".into(),
        };
        certificate.omission_proofs = vec![omission.clone()];
        let bundle = CanonicalOrderPublicationBundle {
            bulletin_commitment: certificate.bulletin_commitment.clone(),
            bulletin_entries: build_bulletin_surface_entries(header.height, &ordered_transactions)
                .unwrap(),
            bulletin_availability_certificate: certificate
                .bulletin_availability_certificate
                .clone(),
            canonical_order_certificate: certificate.clone(),
        };

        let mut state = MockState::default();
        with_ctx(|ctx| {
            run_async(registry.handle_service_call(
                &mut state,
                "publish_aft_canonical_order_artifact_bundle@v1",
                &codec::to_bytes_canonical(&bundle).unwrap(),
                ctx,
            ))
            .unwrap();
        });

        let stored_bulletin = state
            .get(&aft_bulletin_commitment_key(header.height))
            .unwrap()
            .expect("bulletin stored");
        let restored_bulletin: BulletinCommitment =
            codec::from_bytes_canonical(&stored_bulletin).unwrap();
        assert_eq!(restored_bulletin, bundle.bulletin_commitment);

        let stored_entry = state
            .get(&aft_bulletin_entry_key(
                header.height,
                &bundle.bulletin_entries[0].tx_hash,
            ))
            .unwrap()
            .expect("bulletin entry stored");
        let restored_entry: BulletinSurfaceEntry =
            codec::from_bytes_canonical(&stored_entry).unwrap();
        assert_eq!(restored_entry, bundle.bulletin_entries[0]);

        let stored_availability = state
            .get(&aft_bulletin_availability_certificate_key(header.height))
            .unwrap()
            .expect("bulletin availability certificate stored");
        let restored_availability: BulletinAvailabilityCertificate =
            codec::from_bytes_canonical(&stored_availability).unwrap();
        assert_eq!(
            restored_availability,
            bundle.bulletin_availability_certificate
        );

        let stored_certificate = state
            .get(&aft_order_certificate_key(header.height))
            .unwrap()
            .expect("order certificate stored");
        let restored_certificate: CanonicalOrderCertificate =
            codec::from_bytes_canonical(&stored_certificate).unwrap();
        assert_eq!(restored_certificate, certificate);

        let stored_close = state
            .get(&aft_canonical_bulletin_close_key(header.height))
            .unwrap()
            .expect("canonical bulletin close stored");
        let restored_close: CanonicalBulletinClose =
            codec::from_bytes_canonical(&stored_close).unwrap();
        assert_eq!(
            restored_close,
            build_canonical_bulletin_close(
                &bundle.bulletin_commitment,
                &bundle.bulletin_availability_certificate,
            )
            .unwrap()
        );

        let stored_omission = state
            .get(&aft_omission_proof_key(header.height, &omission.tx_hash))
            .unwrap()
            .expect("omission stored");
        let restored_omission: OmissionProof =
            codec::from_bytes_canonical(&stored_omission).unwrap();
        assert_eq!(restored_omission, omission);
    }

    #[test]
    fn extracting_published_bulletin_surface_returns_canonical_entries() {
        let registry = production_registry();
        let base_header = ioi_types::app::BlockHeader {
            height: 17,
            view: 3,
            parent_hash: [19u8; 32],
            parent_state_root: StateRoot(vec![1u8; 32]),
            state_root: StateRoot(vec![2u8; 32]),
            transactions_root: Vec::new(),
            timestamp: 1_760_000_123,
            timestamp_ms: 1_760_000_123_000,
            gas_used: 0,
            validator_set: Vec::new(),
            producer_account_id: AccountId([24u8; 32]),
            producer_key_suite: SignatureSuite::ED25519,
            producer_pubkey_hash: [25u8; 32],
            producer_pubkey: Vec::new(),
            signature: Vec::new(),
            oracle_counter: 0,
            oracle_trace_hash: [0u8; 32],
            parent_qc: QuorumCertificate::default(),
            previous_canonical_collapse_commitment_hash: [0u8; 32],
            canonical_collapse_extension_certificate: None,
            publication_frontier: None,
            guardian_certificate: None,
            sealed_finality_proof: None,
            canonical_order_certificate: None,
            timeout_certificate: None,
        };
        let tx_one = ChainTransaction::System(Box::new(SystemTransaction {
            header: SignHeader {
                account_id: AccountId([31u8; 32]),
                nonce: 1,
                chain_id: ChainId(1),
                tx_version: 1,
                session_auth: None,
            },
            payload: SystemPayload::CallService {
                service_id: "guardian_registry".into(),
                method: "publish_aft_bulletin_commitment@v1".into(),
                params: vec![1],
            },
            signature_proof: SignatureProof::default(),
        }));
        let tx_two = ChainTransaction::System(Box::new(SystemTransaction {
            header: SignHeader {
                account_id: AccountId([32u8; 32]),
                nonce: 1,
                chain_id: ChainId(1),
                tx_version: 1,
                session_auth: None,
            },
            payload: SystemPayload::CallService {
                service_id: "guardian_registry".into(),
                method: "publish_aft_canonical_order_artifact_bundle@v1".into(),
                params: vec![2],
            },
            signature_proof: SignatureProof::default(),
        }));

        let ordered_transactions =
            canonicalize_transactions_for_header(&base_header, &[tx_one, tx_two]).unwrap();
        let tx_hashes: Vec<[u8; 32]> = ordered_transactions
            .iter()
            .map(|tx| tx.hash().unwrap())
            .collect();
        let mut header = base_header;
        header.transactions_root = canonical_transaction_root_from_hashes(&tx_hashes).unwrap();

        let certificate =
            build_committed_surface_canonical_order_certificate(&header, &ordered_transactions)
                .unwrap();
        let entries = build_bulletin_surface_entries(header.height, &ordered_transactions).unwrap();
        let bundle = CanonicalOrderPublicationBundle {
            bulletin_commitment: certificate.bulletin_commitment.clone(),
            bulletin_entries: entries.clone(),
            bulletin_availability_certificate: certificate
                .bulletin_availability_certificate
                .clone(),
            canonical_order_certificate: certificate,
        };

        let mut state = MockState::default();
        with_ctx(|ctx| {
            run_async(registry.handle_service_call(
                &mut state,
                "publish_aft_canonical_order_artifact_bundle@v1",
                &codec::to_bytes_canonical(&bundle).unwrap(),
                ctx,
            ))
            .unwrap();
        });

        let extracted = GuardianRegistry::extract_published_bulletin_surface(&state, header.height)
            .unwrap()
            .expect("canonical bulletin surface extracted");
        assert_eq!(extracted, entries);
    }

    #[test]
    fn publishing_aft_canonical_order_artifact_bundle_persists_extractable_close_surface() {
        let registry = production_registry();
        let base_header = ioi_types::app::BlockHeader {
            height: 27,
            view: 2,
            parent_hash: [11u8; 32],
            parent_state_root: StateRoot(vec![1u8; 32]),
            state_root: StateRoot(vec![2u8; 32]),
            transactions_root: Vec::new(),
            timestamp: 1_760_000_333,
            timestamp_ms: 1_760_000_333_000,
            gas_used: 0,
            validator_set: Vec::new(),
            producer_account_id: AccountId([21u8; 32]),
            producer_key_suite: SignatureSuite::ED25519,
            producer_pubkey_hash: [22u8; 32],
            producer_pubkey: Vec::new(),
            signature: Vec::new(),
            oracle_counter: 0,
            oracle_trace_hash: [0u8; 32],
            parent_qc: QuorumCertificate::default(),
            previous_canonical_collapse_commitment_hash: [0u8; 32],
            canonical_collapse_extension_certificate: None,
            publication_frontier: None,
            guardian_certificate: None,
            sealed_finality_proof: None,
            canonical_order_certificate: None,
            timeout_certificate: None,
        };
        let tx_one = ChainTransaction::System(Box::new(SystemTransaction {
            header: SignHeader {
                account_id: AccountId([31u8; 32]),
                nonce: 1,
                chain_id: ChainId(1),
                tx_version: 1,
                session_auth: None,
            },
            payload: SystemPayload::CallService {
                service_id: "guardian_registry".into(),
                method: "publish_aft_bulletin_commitment@v1".into(),
                params: vec![1],
            },
            signature_proof: SignatureProof::default(),
        }));
        let tx_two = ChainTransaction::System(Box::new(SystemTransaction {
            header: SignHeader {
                account_id: AccountId([32u8; 32]),
                nonce: 1,
                chain_id: ChainId(1),
                tx_version: 1,
                session_auth: None,
            },
            payload: SystemPayload::CallService {
                service_id: "guardian_registry".into(),
                method: "publish_aft_canonical_order_artifact_bundle@v1".into(),
                params: vec![2],
            },
            signature_proof: SignatureProof::default(),
        }));

        let ordered_transactions =
            canonicalize_transactions_for_header(&base_header, &[tx_one, tx_two]).unwrap();
        let tx_hashes: Vec<[u8; 32]> = ordered_transactions
            .iter()
            .map(|tx| tx.hash().unwrap())
            .collect();
        let mut header = base_header;
        header.transactions_root = canonical_transaction_root_from_hashes(&tx_hashes).unwrap();
        let certificate =
            build_committed_surface_canonical_order_certificate(&header, &ordered_transactions)
                .unwrap();
        let bundle = CanonicalOrderPublicationBundle {
            bulletin_commitment: certificate.bulletin_commitment.clone(),
            bulletin_entries: build_bulletin_surface_entries(header.height, &ordered_transactions)
                .unwrap(),
            bulletin_availability_certificate: certificate
                .bulletin_availability_certificate
                .clone(),
            canonical_order_certificate: certificate.clone(),
        };

        let mut state = MockState::default();
        with_ctx(|ctx| {
            run_async(registry.handle_service_call(
                &mut state,
                "publish_aft_canonical_order_artifact_bundle@v1",
                &codec::to_bytes_canonical(&bundle).unwrap(),
                ctx,
            ))
            .unwrap();
        });

        let extracted = GuardianRegistry::extract_published_bulletin_surface(&state, header.height)
            .unwrap()
            .expect("extractable close surface");
        assert_eq!(extracted, bundle.bulletin_entries);
        let required = GuardianRegistry::require_published_bulletin_surface(&state, header.height)
            .expect("strict extraction surface");
        assert_eq!(required, bundle.bulletin_entries);

        let stored_close = state
            .get(&aft_canonical_bulletin_close_key(header.height))
            .unwrap()
            .expect("canonical bulletin close stored");
        let restored_close: CanonicalBulletinClose =
            codec::from_bytes_canonical(&stored_close).unwrap();
        assert_eq!(
            restored_close,
            build_canonical_bulletin_close(
                &bundle.bulletin_commitment,
                &bundle.bulletin_availability_certificate,
            )
            .unwrap()
        );
    }

    #[test]
    fn publishing_aft_order_certificate_legacy_method_is_rejected() {
        let registry = production_registry();
        let bulletin = BulletinCommitment {
            height: 41,
            cutoff_timestamp_ms: 1_760_000_444,
            bulletin_root: [71u8; 32],
            entry_count: 2,
        };
        let availability_certificate = BulletinAvailabilityCertificate {
            height: 41,
            bulletin_commitment_hash: ioi_types::app::canonical_bulletin_commitment_hash(&bulletin)
                .unwrap(),
            recoverability_root: [72u8; 32],
        };
        let certificate = CanonicalOrderCertificate {
            height: 41,
            bulletin_commitment: bulletin.clone(),
            bulletin_availability_certificate: availability_certificate.clone(),
            randomness_beacon: [73u8; 32],
            ordered_transactions_root_hash: [74u8; 32],
            resulting_state_root_hash: [75u8; 32],
            proof: CanonicalOrderProof {
                proof_system: CanonicalOrderProofSystem::HashBindingV1,
                public_inputs_hash: [76u8; 32],
                proof_bytes: vec![77u8; 32],
            },
            omission_proofs: Vec::new(),
        };

        let mut state = MockState::default();
        with_ctx(|ctx| {
            run_async(registry.handle_service_call(
                &mut state,
                "publish_aft_bulletin_commitment@v1",
                &codec::to_bytes_canonical(&bulletin).unwrap(),
                ctx,
            ))
            .unwrap();
            run_async(registry.handle_service_call(
                &mut state,
                "publish_aft_bulletin_availability_certificate@v1",
                &codec::to_bytes_canonical(&availability_certificate).unwrap(),
                ctx,
            ))
            .unwrap();
            let err = run_async(registry.handle_service_call(
                &mut state,
                "publish_aft_order_certificate@v1",
                &codec::to_bytes_canonical(&certificate).unwrap(),
                ctx,
            ))
            .unwrap_err();
            assert!(err
                .to_string()
                .contains("publish_aft_order_certificate@v1 is retired"));
        });
    }

    #[test]
    fn publishing_aft_canonical_order_abort_persists_registry_state() {
        let registry = production_registry();
        let abort = CanonicalOrderAbort {
            height: 44,
            reason: CanonicalOrderAbortReason::InvalidProofBinding,
            details: "proof-carried canonical-order certificate failed binding verification".into(),
            bulletin_commitment_hash: [101u8; 32],
            bulletin_availability_certificate_hash: [102u8; 32],
            bulletin_close_hash: [103u8; 32],
            canonical_order_certificate_hash: [104u8; 32],
        };

        let mut state = MockState::default();
        with_ctx(|ctx| {
            run_async(registry.handle_service_call(
                &mut state,
                "publish_aft_canonical_order_abort@v1",
                &codec::to_bytes_canonical(&abort).unwrap(),
                ctx,
            ))
            .unwrap();
        });

        let stored_abort = state
            .get(&aft_canonical_order_abort_key(abort.height))
            .unwrap()
            .expect("canonical-order abort stored");
        let restored_abort: CanonicalOrderAbort =
            codec::from_bytes_canonical(&stored_abort).unwrap();
        assert_eq!(restored_abort, abort);
    }

    #[test]
    fn publishing_aft_canonical_collapse_object_persists_registry_state() {
        let registry = production_registry();
        let base_header = ioi_types::app::BlockHeader {
            height: 2,
            view: 2,
            parent_hash: [121u8; 32],
            parent_state_root: StateRoot(vec![1u8; 32]),
            state_root: StateRoot(vec![2u8; 32]),
            transactions_root: Vec::new(),
            timestamp: 1_760_000_888,
            timestamp_ms: 1_760_000_888_000,
            gas_used: 0,
            validator_set: Vec::new(),
            producer_account_id: AccountId([122u8; 32]),
            producer_key_suite: SignatureSuite::ED25519,
            producer_pubkey_hash: [123u8; 32],
            producer_pubkey: Vec::new(),
            signature: Vec::new(),
            oracle_counter: 0,
            oracle_trace_hash: [0u8; 32],
            parent_qc: QuorumCertificate::default(),
            previous_canonical_collapse_commitment_hash: [0u8; 32],
            canonical_collapse_extension_certificate: None,
            publication_frontier: None,
            guardian_certificate: None,
            sealed_finality_proof: None,
            canonical_order_certificate: None,
            timeout_certificate: None,
        };
        let tx_one = ChainTransaction::System(Box::new(SystemTransaction {
            header: SignHeader {
                account_id: AccountId([124u8; 32]),
                nonce: 1,
                chain_id: ChainId(1),
                tx_version: 1,
                session_auth: None,
            },
            payload: SystemPayload::CallService {
                service_id: "guardian_registry".into(),
                method: "publish_aft_bulletin_commitment@v1".into(),
                params: vec![1],
            },
            signature_proof: SignatureProof::default(),
        }));
        let tx_two = ChainTransaction::System(Box::new(SystemTransaction {
            header: SignHeader {
                account_id: AccountId([125u8; 32]),
                nonce: 1,
                chain_id: ChainId(1),
                tx_version: 1,
                session_auth: None,
            },
            payload: SystemPayload::CallService {
                service_id: "guardian_registry".into(),
                method: "publish_aft_canonical_order_artifact_bundle@v1".into(),
                params: vec![2],
            },
            signature_proof: SignatureProof::default(),
        }));
        let ordered_transactions =
            canonicalize_transactions_for_header(&base_header, &[tx_one, tx_two]).unwrap();
        let tx_hashes: Vec<[u8; 32]> = ordered_transactions
            .iter()
            .map(|tx| tx.hash().unwrap())
            .collect();
        let mut header = base_header;
        header.transactions_root = canonical_transaction_root_from_hashes(&tx_hashes).unwrap();
        header.canonical_order_certificate = Some(
            build_committed_surface_canonical_order_certificate(&header, &ordered_transactions)
                .unwrap(),
        );
        let mut previous = CanonicalCollapseObject {
            height: header.height - 1,
            previous_canonical_collapse_commitment_hash: [0u8; 32],
            continuity_accumulator_hash: [0u8; 32],
            continuity_recursive_proof: Default::default(),
            ordering: Default::default(),
            sealing: None,
            transactions_root_hash: [201u8; 32],
            resulting_state_root_hash: [202u8; 32],
            archived_recovered_history_checkpoint_hash: [0u8; 32],
            archived_recovered_history_profile_activation_hash: [0u8; 32],
            archived_recovered_history_retention_receipt_hash: [0u8; 32],
        };
        ioi_types::app::bind_canonical_collapse_continuity(&mut previous, None)
            .expect("bind previous continuity");
        header.parent_state_root = StateRoot(previous.resulting_state_root_hash.to_vec());
        header.previous_canonical_collapse_commitment_hash =
            ioi_types::app::canonical_collapse_commitment_hash_from_object(&previous)
                .expect("previous canonical collapse commitment hash");
        header.canonical_collapse_extension_certificate = Some(
            ioi_types::app::canonical_collapse_extension_certificate(header.height, &previous)
                .unwrap(),
        );
        let collapse = ioi_types::app::derive_canonical_collapse_object_with_previous(
            &header,
            &ordered_transactions,
            Some(&previous),
        )
        .expect("collapse");

        let mut state = MockState::default();
        state
            .insert(
                &aft_canonical_collapse_object_key(previous.height),
                &codec::to_bytes_canonical(&previous).unwrap(),
            )
            .unwrap();
        with_ctx(|ctx| {
            run_async(registry.handle_service_call(
                &mut state,
                "publish_aft_canonical_collapse_object@v1",
                &codec::to_bytes_canonical(&collapse).unwrap(),
                ctx,
            ))
            .unwrap();
        });

        let stored = state
            .get(&aft_canonical_collapse_object_key(collapse.height))
            .unwrap()
            .expect("canonical collapse object stored");
        let restored: CanonicalCollapseObject = codec::from_bytes_canonical(&stored).unwrap();
        assert_eq!(restored, collapse);
    }

    #[test]
    fn publishing_conflicting_aft_canonical_collapse_object_is_rejected() {
        let registry = production_registry();
        let previous = CanonicalCollapseObject {
            height: 46,
            previous_canonical_collapse_commitment_hash: [0u8; 32],
            continuity_accumulator_hash: [0u8; 32],
            continuity_recursive_proof: Default::default(),
            ordering: Default::default(),
            sealing: None,
            transactions_root_hash: [138u8; 32],
            resulting_state_root_hash: [139u8; 32],
            archived_recovered_history_checkpoint_hash: [0u8; 32],
            archived_recovered_history_profile_activation_hash: [0u8; 32],
            archived_recovered_history_retention_receipt_hash: [0u8; 32],
        };
        let mut collapse = CanonicalCollapseObject {
            height: 47,
            previous_canonical_collapse_commitment_hash:
                ioi_types::app::canonical_collapse_commitment_hash_from_object(&previous).unwrap(),
            continuity_accumulator_hash: [0u8; 32],
            continuity_recursive_proof: Default::default(),
            ordering: ioi_types::app::CanonicalOrderingCollapse {
                height: 47,
                kind: CanonicalCollapseKind::Abort,
                ..Default::default()
            },
            sealing: None,
            transactions_root_hash: [140u8; 32],
            resulting_state_root_hash: [141u8; 32],
            archived_recovered_history_checkpoint_hash: [0u8; 32],
            archived_recovered_history_profile_activation_hash: [0u8; 32],
            archived_recovered_history_retention_receipt_hash: [0u8; 32],
        };
        ioi_types::app::bind_canonical_collapse_continuity(&mut collapse, Some(&previous)).unwrap();
        let mut conflicting = collapse.clone();
        conflicting.resulting_state_root_hash = [142u8; 32];
        ioi_types::app::bind_canonical_collapse_continuity(&mut conflicting, Some(&previous))
            .unwrap();

        let mut state = MockState::default();
        state
            .insert(
                &aft_canonical_collapse_object_key(previous.height),
                &codec::to_bytes_canonical(&previous).unwrap(),
            )
            .unwrap();
        with_ctx(|ctx| {
            run_async(registry.handle_service_call(
                &mut state,
                "publish_aft_canonical_collapse_object@v1",
                &codec::to_bytes_canonical(&collapse).unwrap(),
                ctx,
            ))
            .unwrap();
            let err = run_async(registry.handle_service_call(
                &mut state,
                "publish_aft_canonical_collapse_object@v1",
                &codec::to_bytes_canonical(&conflicting).unwrap(),
                ctx,
            ))
            .unwrap_err();
            assert!(err
                .to_string()
                .contains("conflicting canonical collapse object already published"));
        });
    }

    #[test]
    fn publishing_aft_canonical_collapse_object_with_wrong_previous_hash_is_rejected() {
        let registry = production_registry();
        let previous = CanonicalCollapseObject {
            height: 46,
            previous_canonical_collapse_commitment_hash: [0u8; 32],
            continuity_accumulator_hash: [0u8; 32],
            continuity_recursive_proof: Default::default(),
            ordering: Default::default(),
            sealing: None,
            transactions_root_hash: [150u8; 32],
            resulting_state_root_hash: [151u8; 32],
            archived_recovered_history_checkpoint_hash: [0u8; 32],
            archived_recovered_history_profile_activation_hash: [0u8; 32],
            archived_recovered_history_retention_receipt_hash: [0u8; 32],
        };
        let mut collapse = CanonicalCollapseObject {
            height: 47,
            previous_canonical_collapse_commitment_hash: [0xFFu8; 32],
            continuity_accumulator_hash: [0u8; 32],
            continuity_recursive_proof: Default::default(),
            ordering: ioi_types::app::CanonicalOrderingCollapse {
                height: 47,
                kind: CanonicalCollapseKind::Abort,
                ..Default::default()
            },
            sealing: None,
            transactions_root_hash: [152u8; 32],
            resulting_state_root_hash: [153u8; 32],
            archived_recovered_history_checkpoint_hash: [0u8; 32],
            archived_recovered_history_profile_activation_hash: [0u8; 32],
            archived_recovered_history_retention_receipt_hash: [0u8; 32],
        };
        ioi_types::app::bind_canonical_collapse_continuity(&mut collapse, Some(&previous)).unwrap();
        collapse.previous_canonical_collapse_commitment_hash = [0xFFu8; 32];

        let mut state = MockState::default();
        state
            .insert(
                &aft_canonical_collapse_object_key(previous.height),
                &codec::to_bytes_canonical(&previous).unwrap(),
            )
            .unwrap();
        with_ctx(|ctx| {
            let err = run_async(registry.handle_service_call(
                &mut state,
                "publish_aft_canonical_collapse_object@v1",
                &codec::to_bytes_canonical(&collapse).unwrap(),
                ctx,
            ))
            .unwrap_err();
            assert!(err
                .to_string()
                .contains("canonical collapse continuity commitment hash mismatch"));
        });
    }

    #[test]
    fn publishing_aft_canonical_order_artifact_bundle_with_missing_entry_is_rejected() {
        let registry = production_registry();
        let base_header = ioi_types::app::BlockHeader {
            height: 42,
            view: 4,
            parent_hash: [81u8; 32],
            parent_state_root: StateRoot(vec![1u8; 32]),
            state_root: StateRoot(vec![2u8; 32]),
            transactions_root: Vec::new(),
            timestamp: 1_760_000_555,
            timestamp_ms: 1_760_000_555_000,
            gas_used: 0,
            validator_set: Vec::new(),
            producer_account_id: AccountId([82u8; 32]),
            producer_key_suite: SignatureSuite::ED25519,
            producer_pubkey_hash: [83u8; 32],
            producer_pubkey: Vec::new(),
            signature: Vec::new(),
            oracle_counter: 0,
            oracle_trace_hash: [0u8; 32],
            parent_qc: QuorumCertificate::default(),
            previous_canonical_collapse_commitment_hash: [0u8; 32],
            canonical_collapse_extension_certificate: None,
            publication_frontier: None,
            guardian_certificate: None,
            sealed_finality_proof: None,
            canonical_order_certificate: None,
            timeout_certificate: None,
        };
        let tx_one = ChainTransaction::System(Box::new(SystemTransaction {
            header: SignHeader {
                account_id: AccountId([84u8; 32]),
                nonce: 1,
                chain_id: ChainId(1),
                tx_version: 1,
                session_auth: None,
            },
            payload: SystemPayload::CallService {
                service_id: "guardian_registry".into(),
                method: "publish_aft_bulletin_commitment@v1".into(),
                params: vec![1],
            },
            signature_proof: SignatureProof::default(),
        }));
        let tx_two = ChainTransaction::System(Box::new(SystemTransaction {
            header: SignHeader {
                account_id: AccountId([85u8; 32]),
                nonce: 1,
                chain_id: ChainId(1),
                tx_version: 1,
                session_auth: None,
            },
            payload: SystemPayload::CallService {
                service_id: "guardian_registry".into(),
                method: "publish_aft_canonical_order_artifact_bundle@v1".into(),
                params: vec![2],
            },
            signature_proof: SignatureProof::default(),
        }));

        let ordered_transactions =
            canonicalize_transactions_for_header(&base_header, &[tx_one, tx_two]).unwrap();
        let tx_hashes: Vec<[u8; 32]> = ordered_transactions
            .iter()
            .map(|tx| tx.hash().unwrap())
            .collect();
        let mut header = base_header;
        header.transactions_root = canonical_transaction_root_from_hashes(&tx_hashes).unwrap();
        let certificate =
            build_committed_surface_canonical_order_certificate(&header, &ordered_transactions)
                .unwrap();
        let mut bundle = CanonicalOrderPublicationBundle {
            bulletin_commitment: certificate.bulletin_commitment.clone(),
            bulletin_entries: build_bulletin_surface_entries(header.height, &ordered_transactions)
                .unwrap(),
            bulletin_availability_certificate: certificate
                .bulletin_availability_certificate
                .clone(),
            canonical_order_certificate: certificate.clone(),
        };
        bundle.bulletin_entries.pop();

        let mut state = MockState::default();
        with_ctx(|ctx| {
            let err = run_async(registry.handle_service_call(
                &mut state,
                "publish_aft_canonical_order_artifact_bundle@v1",
                &codec::to_bytes_canonical(&bundle).unwrap(),
                ctx,
            ))
            .unwrap_err();
            assert!(err
                .to_string()
                .contains("published bulletin surface does not rebuild the bulletin commitment"));
        });
    }

    #[test]
    fn publishing_aft_canonical_order_artifact_bundle_with_wrong_height_is_rejected() {
        let registry = production_registry();
        let base_header = ioi_types::app::BlockHeader {
            height: 43,
            view: 4,
            parent_hash: [91u8; 32],
            parent_state_root: StateRoot(vec![1u8; 32]),
            state_root: StateRoot(vec![2u8; 32]),
            transactions_root: Vec::new(),
            timestamp: 1_760_000_666,
            timestamp_ms: 1_760_000_666_000,
            gas_used: 0,
            validator_set: Vec::new(),
            producer_account_id: AccountId([92u8; 32]),
            producer_key_suite: SignatureSuite::ED25519,
            producer_pubkey_hash: [93u8; 32],
            producer_pubkey: Vec::new(),
            signature: Vec::new(),
            oracle_counter: 0,
            oracle_trace_hash: [0u8; 32],
            parent_qc: QuorumCertificate::default(),
            previous_canonical_collapse_commitment_hash: [0u8; 32],
            canonical_collapse_extension_certificate: None,
            publication_frontier: None,
            guardian_certificate: None,
            sealed_finality_proof: None,
            canonical_order_certificate: None,
            timeout_certificate: None,
        };
        let tx_one = ChainTransaction::System(Box::new(SystemTransaction {
            header: SignHeader {
                account_id: AccountId([94u8; 32]),
                nonce: 1,
                chain_id: ChainId(1),
                tx_version: 1,
                session_auth: None,
            },
            payload: SystemPayload::CallService {
                service_id: "guardian_registry".into(),
                method: "publish_aft_bulletin_commitment@v1".into(),
                params: vec![1],
            },
            signature_proof: SignatureProof::default(),
        }));
        let tx_two = ChainTransaction::System(Box::new(SystemTransaction {
            header: SignHeader {
                account_id: AccountId([95u8; 32]),
                nonce: 1,
                chain_id: ChainId(1),
                tx_version: 1,
                session_auth: None,
            },
            payload: SystemPayload::CallService {
                service_id: "guardian_registry".into(),
                method: "publish_aft_canonical_order_artifact_bundle@v1".into(),
                params: vec![2],
            },
            signature_proof: SignatureProof::default(),
        }));

        let ordered_transactions =
            canonicalize_transactions_for_header(&base_header, &[tx_one, tx_two]).unwrap();
        let tx_hashes: Vec<[u8; 32]> = ordered_transactions
            .iter()
            .map(|tx| tx.hash().unwrap())
            .collect();
        let mut header = base_header;
        header.transactions_root = canonical_transaction_root_from_hashes(&tx_hashes).unwrap();
        let certificate =
            build_committed_surface_canonical_order_certificate(&header, &ordered_transactions)
                .unwrap();
        let mut bundle = CanonicalOrderPublicationBundle {
            bulletin_commitment: certificate.bulletin_commitment.clone(),
            bulletin_entries: build_bulletin_surface_entries(header.height, &ordered_transactions)
                .unwrap(),
            bulletin_availability_certificate: certificate
                .bulletin_availability_certificate
                .clone(),
            canonical_order_certificate: certificate.clone(),
        };
        bundle.bulletin_entries[0].height = header.height + 1;

        let mut state = MockState::default();
        with_ctx(|ctx| {
            let err = run_async(registry.handle_service_call(
                &mut state,
                "publish_aft_canonical_order_artifact_bundle@v1",
                &codec::to_bytes_canonical(&bundle).unwrap(),
                ctx,
            ))
            .unwrap_err();
            assert!(err
                .to_string()
                .contains("bulletin surface entries do not match the target slot height"));
        });
    }

    #[test]
    fn publishing_aft_canonical_order_artifact_bundle_after_abort_is_rejected() {
        let registry = production_registry();
        let base_header = ioi_types::app::BlockHeader {
            height: 45,
            view: 4,
            parent_hash: [111u8; 32],
            parent_state_root: StateRoot(vec![1u8; 32]),
            state_root: StateRoot(vec![2u8; 32]),
            transactions_root: Vec::new(),
            timestamp: 1_760_000_777,
            timestamp_ms: 1_760_000_777_000,
            gas_used: 0,
            validator_set: Vec::new(),
            producer_account_id: AccountId([112u8; 32]),
            producer_key_suite: SignatureSuite::ED25519,
            producer_pubkey_hash: [113u8; 32],
            producer_pubkey: Vec::new(),
            signature: Vec::new(),
            oracle_counter: 0,
            oracle_trace_hash: [0u8; 32],
            parent_qc: QuorumCertificate::default(),
            previous_canonical_collapse_commitment_hash: [0u8; 32],
            canonical_collapse_extension_certificate: None,
            publication_frontier: None,
            guardian_certificate: None,
            sealed_finality_proof: None,
            canonical_order_certificate: None,
            timeout_certificate: None,
        };
        let tx_one = ChainTransaction::System(Box::new(SystemTransaction {
            header: SignHeader {
                account_id: AccountId([114u8; 32]),
                nonce: 1,
                chain_id: ChainId(1),
                tx_version: 1,
                session_auth: None,
            },
            payload: SystemPayload::CallService {
                service_id: "guardian_registry".into(),
                method: "publish_aft_bulletin_commitment@v1".into(),
                params: vec![1],
            },
            signature_proof: SignatureProof::default(),
        }));
        let tx_two = ChainTransaction::System(Box::new(SystemTransaction {
            header: SignHeader {
                account_id: AccountId([115u8; 32]),
                nonce: 1,
                chain_id: ChainId(1),
                tx_version: 1,
                session_auth: None,
            },
            payload: SystemPayload::CallService {
                service_id: "guardian_registry".into(),
                method: "publish_aft_canonical_order_artifact_bundle@v1".into(),
                params: vec![2],
            },
            signature_proof: SignatureProof::default(),
        }));

        let ordered_transactions =
            canonicalize_transactions_for_header(&base_header, &[tx_one, tx_two]).unwrap();
        let tx_hashes: Vec<[u8; 32]> = ordered_transactions
            .iter()
            .map(|tx| tx.hash().unwrap())
            .collect();
        let mut header = base_header;
        header.transactions_root = canonical_transaction_root_from_hashes(&tx_hashes).unwrap();
        let certificate =
            build_committed_surface_canonical_order_certificate(&header, &ordered_transactions)
                .unwrap();
        let bundle = CanonicalOrderPublicationBundle {
            bulletin_commitment: certificate.bulletin_commitment.clone(),
            bulletin_entries: build_bulletin_surface_entries(header.height, &ordered_transactions)
                .unwrap(),
            bulletin_availability_certificate: certificate
                .bulletin_availability_certificate
                .clone(),
            canonical_order_certificate: certificate,
        };
        let abort = CanonicalOrderAbort {
            height: header.height,
            reason: CanonicalOrderAbortReason::MissingOrderCertificate,
            details: "slot already collapsed to abort".into(),
            bulletin_commitment_hash: [116u8; 32],
            bulletin_availability_certificate_hash: [117u8; 32],
            bulletin_close_hash: [0u8; 32],
            canonical_order_certificate_hash: [0u8; 32],
        };

        let mut state = MockState::default();
        with_ctx(|ctx| {
            run_async(registry.handle_service_call(
                &mut state,
                "publish_aft_canonical_order_abort@v1",
                &codec::to_bytes_canonical(&abort).unwrap(),
                ctx,
            ))
            .unwrap();
            let err = run_async(registry.handle_service_call(
                &mut state,
                "publish_aft_canonical_order_artifact_bundle@v1",
                &codec::to_bytes_canonical(&bundle).unwrap(),
                ctx,
            ))
            .unwrap_err();
            assert!(err
                .to_string()
                .contains("after canonical abort publication"));
        });
    }

    #[test]
    fn publishing_conflicting_publication_frontier_materializes_contradiction_and_abort() {
        let registry = production_registry();
        let frontier = PublicationFrontier {
            height: 54,
            view: 2,
            counter: 54,
            parent_frontier_hash: [1u8; 32],
            bulletin_commitment_hash: [2u8; 32],
            ordered_transactions_root_hash: [3u8; 32],
            availability_receipt_hash: [4u8; 32],
        };
        let conflicting = PublicationFrontier {
            view: 3,
            bulletin_commitment_hash: [5u8; 32],
            availability_receipt_hash: [6u8; 32],
            ..frontier.clone()
        };

        let mut state = MockState::default();
        with_ctx(|ctx| {
            run_async(registry.handle_service_call(
                &mut state,
                "publish_aft_publication_frontier@v1",
                &codec::to_bytes_canonical(&frontier).unwrap(),
                ctx,
            ))
            .unwrap();
            run_async(registry.handle_service_call(
                &mut state,
                "publish_aft_publication_frontier@v1",
                &codec::to_bytes_canonical(&conflicting).unwrap(),
                ctx,
            ))
            .unwrap();
        });

        let contradiction: PublicationFrontierContradiction = codec::from_bytes_canonical(
            &state
                .get(&aft_publication_frontier_contradiction_key(frontier.height))
                .unwrap()
                .expect("contradiction stored"),
        )
        .unwrap();
        assert_eq!(
            contradiction.kind,
            PublicationFrontierContradictionKind::ConflictingFrontier
        );
        assert_eq!(contradiction.candidate_frontier, conflicting);
        assert_eq!(contradiction.reference_frontier, frontier);

        let abort: CanonicalOrderAbort = codec::from_bytes_canonical(
            &state
                .get(&aft_canonical_order_abort_key(54))
                .unwrap()
                .expect("abort stored"),
        )
        .unwrap();
        assert_eq!(
            abort.reason,
            CanonicalOrderAbortReason::PublicationFrontierConflict
        );
        assert!(state
            .get(&aft_publication_frontier_key(54))
            .unwrap()
            .is_none());
    }

    #[test]
    fn publishing_stale_publication_frontier_materializes_contradiction_and_abort() {
        let registry = production_registry();
        let previous = PublicationFrontier {
            height: 63,
            view: 1,
            counter: 63,
            parent_frontier_hash: [7u8; 32],
            bulletin_commitment_hash: [8u8; 32],
            ordered_transactions_root_hash: [9u8; 32],
            availability_receipt_hash: [10u8; 32],
        };
        let stale = PublicationFrontier {
            height: 64,
            view: 2,
            counter: 64,
            parent_frontier_hash: [11u8; 32],
            bulletin_commitment_hash: [12u8; 32],
            ordered_transactions_root_hash: [13u8; 32],
            availability_receipt_hash: [14u8; 32],
        };

        let mut state = MockState::default();
        state
            .insert(
                &aft_publication_frontier_key(previous.height),
                &codec::to_bytes_canonical(&previous).unwrap(),
            )
            .unwrap();

        with_ctx(|ctx| {
            run_async(registry.handle_service_call(
                &mut state,
                "publish_aft_publication_frontier@v1",
                &codec::to_bytes_canonical(&stale).unwrap(),
                ctx,
            ))
            .unwrap();
        });

        let contradiction: PublicationFrontierContradiction = codec::from_bytes_canonical(
            &state
                .get(&aft_publication_frontier_contradiction_key(stale.height))
                .unwrap()
                .expect("contradiction stored"),
        )
        .unwrap();
        assert_eq!(
            contradiction.kind,
            PublicationFrontierContradictionKind::StaleParentLink
        );
        assert_eq!(contradiction.candidate_frontier, stale);
        assert_eq!(contradiction.reference_frontier, previous);

        let abort: CanonicalOrderAbort = codec::from_bytes_canonical(
            &state
                .get(&aft_canonical_order_abort_key(64))
                .unwrap()
                .expect("abort stored"),
        )
        .unwrap();
        assert_eq!(
            abort.reason,
            CanonicalOrderAbortReason::PublicationFrontierStale
        );
        assert!(state
            .get(&aft_publication_frontier_key(64))
            .unwrap()
            .is_none());
    }

    #[test]
    fn publishing_recovery_registry_objects_round_trips_and_preserves_multiple_receipts() {
        let registry = production_registry();
        let capsule = sample_recovery_capsule(71);
        let witness_manifest_hash = [17u8; 32];
        let certificate =
            sample_recovery_witness_certificate(&capsule, witness_manifest_hash, [18u8; 32]);
        let receipt_a = RecoveryShareReceipt {
            height: capsule.height,
            witness_manifest_hash,
            block_commitment_hash: [19u8; 32],
            share_commitment_hash: certificate.share_commitment_hash,
        };
        let receipt_b = RecoveryShareReceipt {
            height: capsule.height,
            witness_manifest_hash,
            block_commitment_hash: [20u8; 32],
            share_commitment_hash: certificate.share_commitment_hash,
        };

        let mut state = MockState::default();
        with_ctx(|ctx| {
            for (method, params) in [
                (
                    "publish_aft_recovery_capsule@v1",
                    codec::to_bytes_canonical(&capsule).unwrap(),
                ),
                (
                    "publish_aft_recovery_witness_certificate@v1",
                    codec::to_bytes_canonical(&certificate).unwrap(),
                ),
                (
                    "publish_aft_recovery_share_receipt@v1",
                    codec::to_bytes_canonical(&receipt_a).unwrap(),
                ),
                (
                    "publish_aft_recovery_share_receipt@v1",
                    codec::to_bytes_canonical(&receipt_b).unwrap(),
                ),
            ] {
                run_async(registry.handle_service_call(&mut state, method, &params, ctx)).unwrap();
            }
        });

        assert_eq!(
            GuardianRegistry::load_recovery_capsule(&state, capsule.height).unwrap(),
            Some(capsule.clone())
        );
        assert_eq!(
            GuardianRegistry::load_recovery_witness_certificate(
                &state,
                capsule.height,
                &witness_manifest_hash,
            )
            .unwrap(),
            Some(certificate.clone())
        );
        assert_eq!(
            GuardianRegistry::load_recovery_share_receipts(
                &state,
                capsule.height,
                &witness_manifest_hash
            )
            .unwrap(),
            vec![receipt_a.clone(), receipt_b.clone()]
        );
        assert_eq!(
            GuardianRegistry::load_missing_recovery_share(
                &state,
                capsule.height,
                &witness_manifest_hash
            )
            .unwrap(),
            None
        );
        assert!(state
            .get(&aft_recovery_capsule_key(capsule.height))
            .unwrap()
            .is_some());
        assert!(state
            .get(&aft_recovery_witness_certificate_key(
                capsule.height,
                &witness_manifest_hash,
            ))
            .unwrap()
            .is_some());
        assert!(state
            .get(&aft_recovery_share_receipt_key(
                capsule.height,
                &witness_manifest_hash,
                &receipt_a.block_commitment_hash,
            ))
            .unwrap()
            .is_some());
        assert!(state
            .get(&aft_recovery_share_receipt_key(
                capsule.height,
                &witness_manifest_hash,
                &receipt_b.block_commitment_hash,
            ))
            .unwrap()
            .is_some());
    }

    #[test]
    fn publishing_recovery_share_material_round_trips_after_matching_receipt() {
        let registry = production_registry();
        let capsule = sample_recovery_capsule(71);
        let witness_manifest_hash = [17u8; 32];
        let certificate =
            sample_recovery_witness_certificate(&capsule, witness_manifest_hash, [18u8; 32]);
        let material = RecoveryShareMaterial {
            height: capsule.height,
            witness_manifest_hash,
            block_commitment_hash: [19u8; 32],
            coding: xor_recovery_coding(3, 2),
            share_index: 0,
            share_commitment_hash: certificate.share_commitment_hash,
            material_bytes: vec![0xaa, 0xbb, 0xcc],
        };
        let receipt = material.to_recovery_share_receipt();

        let mut state = MockState::default();
        with_ctx(|ctx| {
            for (method, params) in [
                (
                    "publish_aft_recovery_capsule@v1",
                    codec::to_bytes_canonical(&capsule).unwrap(),
                ),
                (
                    "publish_aft_recovery_witness_certificate@v1",
                    codec::to_bytes_canonical(&certificate).unwrap(),
                ),
                (
                    "publish_aft_recovery_share_receipt@v1",
                    codec::to_bytes_canonical(&receipt).unwrap(),
                ),
                (
                    "publish_aft_recovery_share_material@v1",
                    codec::to_bytes_canonical(&material).unwrap(),
                ),
            ] {
                run_async(registry.handle_service_call(&mut state, method, &params, ctx)).unwrap();
            }
        });

        assert_eq!(
            GuardianRegistry::load_recovery_share_materials(
                &state,
                capsule.height,
                &witness_manifest_hash,
            )
            .unwrap(),
            vec![material.clone()]
        );
        assert!(state
            .get(&aft_recovery_share_material_key(
                capsule.height,
                &witness_manifest_hash,
                &material.block_commitment_hash,
            ))
            .unwrap()
            .is_some());
    }

    #[test]
    fn publishing_recovered_publication_bundle_round_trips_after_two_public_reveals() {
        let registry = production_registry();
        let (capsule, certificates, materials, recovered) =
            sample_recovered_publication_bundle_fixture(80, 90);
        let (_, expected_bundle) =
            recover_canonical_order_publication_bundle_from_share_materials(&materials)
                .expect("reconstruct recovered publication bundle");
        let (expected_full_surface, _, _, _) =
            recover_full_canonical_order_surface_from_share_materials(&materials)
                .expect("reconstruct recovered full extractable surface");
        let expected_close = build_canonical_bulletin_close(
            &expected_bundle.bulletin_commitment,
            &expected_bundle.bulletin_availability_certificate,
        )
        .expect("canonical bulletin close");
        let mut expected_surface = expected_bundle.bulletin_entries.clone();
        expected_surface.sort_unstable_by(|left, right| left.tx_hash.cmp(&right.tx_hash));

        let mut state = MockState::default();
        seed_previous_canonical_collapse_placeholder_if_absent(&mut state, recovered.height, 0x97);
        with_ctx(|ctx| {
            run_async(registry.handle_service_call(
                &mut state,
                "publish_aft_recovery_capsule@v1",
                &codec::to_bytes_canonical(&capsule).unwrap(),
                ctx,
            ))
            .unwrap();
            for certificate in &certificates {
                run_async(registry.handle_service_call(
                    &mut state,
                    "publish_aft_recovery_witness_certificate@v1",
                    &codec::to_bytes_canonical(certificate).unwrap(),
                    ctx,
                ))
                .unwrap();
            }
            for material in &materials {
                let receipt = material.to_recovery_share_receipt();
                run_async(registry.handle_service_call(
                    &mut state,
                    "publish_aft_recovery_share_receipt@v1",
                    &codec::to_bytes_canonical(&receipt).unwrap(),
                    ctx,
                ))
                .unwrap();
                run_async(registry.handle_service_call(
                    &mut state,
                    "publish_aft_recovery_share_material@v1",
                    &codec::to_bytes_canonical(material).unwrap(),
                    ctx,
                ))
                .unwrap();
            }
            run_async(registry.handle_service_call(
                &mut state,
                "publish_aft_recovered_publication_bundle@v1",
                &codec::to_bytes_canonical(&recovered).unwrap(),
                ctx,
            ))
            .unwrap();
        });

        assert_eq!(
            GuardianRegistry::load_bulletin_commitment(&state, recovered.height).unwrap(),
            Some(expected_bundle.bulletin_commitment.clone())
        );
        assert_eq!(
            GuardianRegistry::load_bulletin_availability_certificate(&state, recovered.height)
                .unwrap(),
            Some(expected_bundle.bulletin_availability_certificate.clone())
        );
        assert_eq!(
            GuardianRegistry::load_canonical_bulletin_close(&state, recovered.height).unwrap(),
            Some(expected_close)
        );
        assert_eq!(
            recovered.canonical_bulletin_close_hash,
            canonical_bulletin_close_hash(
                &GuardianRegistry::load_canonical_bulletin_close(&state, recovered.height)
                    .unwrap()
                    .expect("persisted bulletin close"),
            )
            .expect("persisted bulletin close hash")
        );
        assert_eq!(
            recovered.recoverable_full_surface_hash,
            canonical_recoverable_slot_payload_v5_hash(&expected_full_surface)
                .expect("recoverable payload v5 hash")
        );
        assert_eq!(
            GuardianRegistry::extract_published_bulletin_surface(&state, recovered.height).unwrap(),
            Some(expected_surface)
        );
        assert_eq!(
            GuardianRegistry::load_recovered_publication_bundles(
                &state,
                recovered.height,
                &recovered.block_commitment_hash,
            )
            .unwrap(),
            vec![recovered.clone()]
        );
        assert!(state
            .get(
                &aft_recovered_publication_bundle_key(
                    recovered.height,
                    &recovered.block_commitment_hash,
                    &recovered.supporting_witness_manifest_hashes,
                )
                .unwrap(),
            )
            .unwrap()
            .is_some());
    }

    #[test]
    fn publishing_recovered_publication_bundles_for_two_consecutive_slots_supports_recovered_only_frontier_chain(
    ) {
        let registry = production_registry();
        let (capsule_a, certificates_a, materials_a, recovered_a) =
            sample_recovered_publication_bundle_fixture_3_of_7(1, 0xa1);
        let (capsule_b, certificates_b, materials_b, recovered_b) =
            sample_recovered_publication_bundle_fixture_3_of_7_with_parent(
                2,
                0xa2,
                recovered_a.block_commitment_hash,
            );
        let (full_surface_a, _, _, surface_a) =
            recover_full_canonical_order_surface_from_share_materials(&materials_a)
                .expect("slot-a recovered full surface");
        let (full_surface_b, _, _, surface_b) =
            recover_full_canonical_order_surface_from_share_materials(&materials_b)
                .expect("slot-b recovered full surface");
        let header_a = recovered_publication_frontier_header(&full_surface_a);
        let frontier_a = ioi_types::app::build_publication_frontier(&header_a, None)
            .expect("slot-a recovered frontier");
        let header_b = recovered_publication_frontier_header(&full_surface_b);
        let frontier_b = ioi_types::app::build_publication_frontier(&header_b, Some(&frontier_a))
            .expect("slot-b recovered frontier");

        let mut state = MockState::default();
        publish_recovered_publication_fixture(
            &registry,
            &mut state,
            &capsule_a,
            &certificates_a,
            &materials_a,
            &recovered_a,
        );
        publish_recovered_publication_fixture(
            &registry,
            &mut state,
            &capsule_b,
            &certificates_b,
            &materials_b,
            &recovered_b,
        );
        with_ctx(|ctx| {
            run_async(registry.handle_service_call(
                &mut state,
                "publish_aft_publication_frontier@v1",
                &codec::to_bytes_canonical(&frontier_a).unwrap(),
                ctx,
            ))
            .unwrap();
            run_async(registry.handle_service_call(
                &mut state,
                "publish_aft_publication_frontier@v1",
                &codec::to_bytes_canonical(&frontier_b).unwrap(),
                ctx,
            ))
            .unwrap();
        });

        ioi_types::app::verify_publication_frontier(&header_a, &frontier_a, None)
            .expect("slot-a recovered frontier should verify");
        ioi_types::app::verify_publication_frontier(&header_b, &frontier_b, Some(&frontier_a))
            .expect("slot-b recovered frontier should verify");
        assert_eq!(
            frontier_b.parent_frontier_hash,
            ioi_types::app::canonical_publication_frontier_hash(&frontier_a)
                .expect("slot-a frontier hash")
        );
        assert_eq!(
            GuardianRegistry::load_publication_frontier(&state, 1).unwrap(),
            Some(frontier_a)
        );
        assert_eq!(
            GuardianRegistry::load_publication_frontier(&state, 2).unwrap(),
            Some(frontier_b)
        );
        assert!(
            GuardianRegistry::load_publication_frontier_contradiction(&state, 1)
                .unwrap()
                .is_none()
        );
        assert!(
            GuardianRegistry::load_publication_frontier_contradiction(&state, 2)
                .unwrap()
                .is_none()
        );
        assert_eq!(
            GuardianRegistry::extract_published_bulletin_surface(&state, 1).unwrap(),
            Some(surface_a)
        );
        assert_eq!(
            GuardianRegistry::extract_published_bulletin_surface(&state, 2).unwrap(),
            Some(surface_b)
        );
    }

    #[test]
    fn publishing_recovered_publication_window_with_middle_omission_abort_supports_recovered_only_bulletin_sequence(
    ) {
        let registry = production_registry_without_accountable_membership_updates();
        let offender = AccountId([0x91u8; 32]);
        let omission_tx_hash = [0xa7u8; 32];
        let (capsule_a, certificates_a, materials_a, recovered_a) =
            sample_recovered_publication_bundle_fixture_3_of_7(1, 0xb1);
        let (capsule_b, certificates_b, materials_b, recovered_b) =
            sample_recovered_publication_bundle_fixture_3_of_7_with_parent_and_omission(
                2,
                0xb2,
                recovered_a.block_commitment_hash,
                offender,
                omission_tx_hash,
            );
        let (capsule_c, certificates_c, materials_c, recovered_c) =
            sample_recovered_publication_bundle_fixture_3_of_7_with_parent(
                3,
                0xb3,
                recovered_b.block_commitment_hash,
            );
        let (full_surface_a, _, _, surface_a) =
            recover_full_canonical_order_surface_from_share_materials(&materials_a)
                .expect("slot-a recovered full surface");
        let (full_surface_b, _, _, _) =
            recover_full_canonical_order_surface_from_share_materials(&materials_b)
                .expect("slot-b recovered full surface");
        let (full_surface_c, _, _, surface_c) =
            recover_full_canonical_order_surface_from_share_materials(&materials_c)
                .expect("slot-c recovered full surface");
        let (_, recovered_bundle_b) =
            recover_canonical_order_publication_bundle_from_share_materials(&materials_b)
                .expect("slot-b recovered publication bundle");
        let omission_b = recovered_bundle_b
            .canonical_order_certificate
            .omission_proofs
            .first()
            .cloned()
            .expect("slot-b recovered omission proof");
        let mut surface_b = recovered_bundle_b.bulletin_entries.clone();
        surface_b.sort_unstable_by(|left, right| left.tx_hash.cmp(&right.tx_hash));
        let header_a = recovered_publication_frontier_header(&full_surface_a);
        let frontier_a = ioi_types::app::build_publication_frontier(&header_a, None)
            .expect("slot-a recovered frontier");
        let header_c = recovered_publication_frontier_header(&full_surface_c);
        let frontier_c = ioi_types::app::build_publication_frontier(&header_c, Some(&frontier_a))
            .expect("slot-c recovered frontier");
        let close_a = build_canonical_bulletin_close(
            &full_surface_a
                .canonical_order_certificate
                .bulletin_commitment,
            &full_surface_a
                .canonical_order_certificate
                .bulletin_availability_certificate,
        )
        .expect("slot-a canonical bulletin close");
        let close_b = build_canonical_bulletin_close(
            &full_surface_b
                .canonical_order_certificate
                .bulletin_commitment,
            &full_surface_b
                .canonical_order_certificate
                .bulletin_availability_certificate,
        )
        .expect("slot-b canonical bulletin close");
        let close_c = build_canonical_bulletin_close(
            &full_surface_c
                .canonical_order_certificate
                .bulletin_commitment,
            &full_surface_c
                .canonical_order_certificate
                .bulletin_availability_certificate,
        )
        .expect("slot-c canonical bulletin close");
        let expected_collapse_a = derive_canonical_collapse_object_from_recovered_surface(
            &full_surface_a,
            &close_a,
            None,
        )
        .expect("slot-a recovered collapse");
        let expected_collapse_b = derive_canonical_collapse_object_from_recovered_surface(
            &full_surface_b,
            &close_b,
            Some(&expected_collapse_a),
        )
        .expect("slot-b recovered collapse");
        let expected_collapse_c = derive_canonical_collapse_object_from_recovered_surface(
            &full_surface_c,
            &close_c,
            Some(&expected_collapse_b),
        )
        .expect("slot-c recovered collapse");

        let mut state = MockState::default();
        state
            .insert(
                VALIDATOR_SET_KEY,
                &write_validator_sets(&validator_sets(&[(18, 1), (145, 1), (19, 1)])).unwrap(),
            )
            .unwrap();

        publish_recovered_publication_fixture(
            &registry,
            &mut state,
            &capsule_a,
            &certificates_a,
            &materials_a,
            &recovered_a,
        );
        publish_recovered_publication_fixture(
            &registry,
            &mut state,
            &capsule_b,
            &certificates_b,
            &materials_b,
            &recovered_b,
        );
        publish_recovered_publication_fixture(
            &registry,
            &mut state,
            &capsule_c,
            &certificates_c,
            &materials_c,
            &recovered_c,
        );
        with_ctx(|ctx| {
            run_async(registry.handle_service_call(
                &mut state,
                "publish_aft_publication_frontier@v1",
                &codec::to_bytes_canonical(&frontier_a).unwrap(),
                ctx,
            ))
            .unwrap();
            run_async(registry.handle_service_call(
                &mut state,
                "publish_aft_publication_frontier@v1",
                &codec::to_bytes_canonical(&frontier_c).unwrap(),
                ctx,
            ))
            .unwrap();
        });

        ioi_types::app::verify_publication_frontier(&header_a, &frontier_a, None)
            .expect("slot-a recovered frontier should verify");

        let slot_b_abort = GuardianRegistry::load_canonical_order_abort(&state, 2)
            .unwrap()
            .expect("slot-b recovered omission should materialize an abort");
        assert_eq!(
            slot_b_abort.reason,
            CanonicalOrderAbortReason::OmissionDominated
        );
        assert_eq!(
            GuardianRegistry::load_canonical_bulletin_close(&state, 1).unwrap(),
            Some(close_a.clone())
        );
        assert_eq!(
            GuardianRegistry::load_canonical_bulletin_close(&state, 2).unwrap(),
            None
        );
        assert_eq!(
            GuardianRegistry::load_canonical_bulletin_close(&state, 3).unwrap(),
            Some(close_c.clone())
        );
        assert_eq!(
            GuardianRegistry::extract_published_bulletin_surface(&state, 1).unwrap(),
            Some(surface_a)
        );
        assert_eq!(
            GuardianRegistry::extract_published_bulletin_surface(&state, 2).unwrap(),
            None
        );
        assert_eq!(
            GuardianRegistry::extract_published_bulletin_surface(&state, 3).unwrap(),
            Some(surface_c)
        );
        assert_eq!(
            GuardianRegistry::load_bulletin_surface_entries(&state, 2).unwrap(),
            surface_b
        );
        let stored_omission: OmissionProof = codec::from_bytes_canonical(
            &state
                .get(&aft_omission_proof_key(
                    omission_b.height,
                    &omission_b.tx_hash,
                ))
                .unwrap()
                .expect("slot-b omission proof stored"),
        )
        .unwrap();
        assert_eq!(stored_omission, omission_b);
        assert_eq!(
            GuardianRegistry::load_publication_frontier(&state, 1).unwrap(),
            Some(frontier_a.clone())
        );
        assert_eq!(
            GuardianRegistry::load_publication_frontier(&state, 2).unwrap(),
            None
        );
        assert_eq!(
            GuardianRegistry::load_publication_frontier(&state, 3).unwrap(),
            Some(frontier_c.clone())
        );
        assert_eq!(
            GuardianRegistry::load_canonical_collapse_object(&state, 1).unwrap(),
            Some(expected_collapse_a.clone())
        );
        assert_eq!(
            GuardianRegistry::load_canonical_collapse_object(&state, 2).unwrap(),
            Some(expected_collapse_b.clone())
        );
        assert_eq!(
            GuardianRegistry::load_canonical_collapse_object(&state, 3).unwrap(),
            Some(expected_collapse_c.clone())
        );
        assert_eq!(
            expected_collapse_b.previous_canonical_collapse_commitment_hash,
            ioi_types::app::canonical_collapse_commitment_hash_from_object(&expected_collapse_a)
                .expect("slot-a canonical collapse commitment")
        );
        assert_eq!(
            expected_collapse_c.previous_canonical_collapse_commitment_hash,
            ioi_types::app::canonical_collapse_commitment_hash_from_object(&expected_collapse_b)
                .expect("slot-b canonical collapse commitment")
        );
        assert_eq!(
            frontier_c.parent_frontier_hash,
            canonical_publication_frontier_hash(&frontier_a)
                .expect("slot-a publication frontier hash")
        );
        assert!(
            GuardianRegistry::load_publication_frontier_contradiction(&state, 1)
                .unwrap()
                .is_none()
        );
        assert!(
            GuardianRegistry::load_publication_frontier_contradiction(&state, 2)
                .unwrap()
                .is_none()
        );
        assert!(
            GuardianRegistry::load_publication_frontier_contradiction(&state, 3)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn extracting_recovered_only_replay_prefix_matches_durable_mixed_window_surface() {
        let registry = production_registry_without_accountable_membership_updates();
        let offender = AccountId([0x81u8; 32]);
        let omission_tx_hash = [0xc7u8; 32];
        let (capsule_a, certificates_a, materials_a, recovered_a) =
            sample_recovered_publication_bundle_fixture_3_of_7(1, 0xc1);
        let (capsule_b, certificates_b, materials_b, recovered_b) =
            sample_recovered_publication_bundle_fixture_3_of_7_with_parent_and_omission(
                2,
                0xc2,
                recovered_a.block_commitment_hash,
                offender,
                omission_tx_hash,
            );
        let (capsule_c, certificates_c, materials_c, recovered_c) =
            sample_recovered_publication_bundle_fixture_3_of_7_with_parent(
                3,
                0xc3,
                recovered_b.block_commitment_hash,
            );
        let (capsule_d, certificates_d, materials_d, recovered_d) =
            sample_recovered_publication_bundle_fixture_3_of_7_with_parent(
                4,
                0xc4,
                recovered_c.block_commitment_hash,
            );
        let (capsule_e, certificates_e, materials_e, recovered_e) =
            sample_recovered_publication_bundle_fixture_3_of_7_with_parent(
                5,
                0xc5,
                recovered_d.block_commitment_hash,
            );
        let (full_surface_a, _, _, _) =
            recover_full_canonical_order_surface_from_share_materials(&materials_a)
                .expect("slot-a recovered full surface");
        let (full_surface_b, _, _, _) =
            recover_full_canonical_order_surface_from_share_materials(&materials_b)
                .expect("slot-b recovered full surface");
        let (full_surface_c, _, _, _) =
            recover_full_canonical_order_surface_from_share_materials(&materials_c)
                .expect("slot-c recovered full surface");
        let (full_surface_d, _, _, _) =
            recover_full_canonical_order_surface_from_share_materials(&materials_d)
                .expect("slot-d recovered full surface");
        let (full_surface_e, _, _, _) =
            recover_full_canonical_order_surface_from_share_materials(&materials_e)
                .expect("slot-e recovered full surface");
        let header_a = recovered_publication_frontier_header(&full_surface_a);
        let frontier_a = ioi_types::app::build_publication_frontier(&header_a, None)
            .expect("slot-a recovered frontier");
        let header_c = recovered_publication_frontier_header(&full_surface_c);
        let frontier_c = ioi_types::app::build_publication_frontier(&header_c, Some(&frontier_a))
            .expect("slot-c recovered frontier");
        let header_d = recovered_publication_frontier_header(&full_surface_d);
        let frontier_d = ioi_types::app::build_publication_frontier(&header_d, Some(&frontier_c))
            .expect("slot-d recovered frontier");
        let header_e = recovered_publication_frontier_header(&full_surface_e);
        let frontier_e = ioi_types::app::build_publication_frontier(&header_e, Some(&frontier_d))
            .expect("slot-e recovered frontier");
        let close_a = build_canonical_bulletin_close(
            &full_surface_a
                .canonical_order_certificate
                .bulletin_commitment,
            &full_surface_a
                .canonical_order_certificate
                .bulletin_availability_certificate,
        )
        .expect("slot-a canonical bulletin close");
        let close_b = build_canonical_bulletin_close(
            &full_surface_b
                .canonical_order_certificate
                .bulletin_commitment,
            &full_surface_b
                .canonical_order_certificate
                .bulletin_availability_certificate,
        )
        .expect("slot-b canonical bulletin close");
        let close_c = build_canonical_bulletin_close(
            &full_surface_c
                .canonical_order_certificate
                .bulletin_commitment,
            &full_surface_c
                .canonical_order_certificate
                .bulletin_availability_certificate,
        )
        .expect("slot-c canonical bulletin close");
        let close_d = build_canonical_bulletin_close(
            &full_surface_d
                .canonical_order_certificate
                .bulletin_commitment,
            &full_surface_d
                .canonical_order_certificate
                .bulletin_availability_certificate,
        )
        .expect("slot-d canonical bulletin close");
        let close_e = build_canonical_bulletin_close(
            &full_surface_e
                .canonical_order_certificate
                .bulletin_commitment,
            &full_surface_e
                .canonical_order_certificate
                .bulletin_availability_certificate,
        )
        .expect("slot-e canonical bulletin close");
        let expected_collapse_a = derive_canonical_collapse_object_from_recovered_surface(
            &full_surface_a,
            &close_a,
            None,
        )
        .expect("slot-a recovered collapse");
        let expected_collapse_b = derive_canonical_collapse_object_from_recovered_surface(
            &full_surface_b,
            &close_b,
            Some(&expected_collapse_a),
        )
        .expect("slot-b recovered collapse");
        let expected_collapse_c = derive_canonical_collapse_object_from_recovered_surface(
            &full_surface_c,
            &close_c,
            Some(&expected_collapse_b),
        )
        .expect("slot-c recovered collapse");
        let expected_collapse_d = derive_canonical_collapse_object_from_recovered_surface(
            &full_surface_d,
            &close_d,
            Some(&expected_collapse_c),
        )
        .expect("slot-d recovered collapse");
        let expected_collapse_e = derive_canonical_collapse_object_from_recovered_surface(
            &full_surface_e,
            &close_e,
            Some(&expected_collapse_d),
        )
        .expect("slot-e recovered collapse");

        let mut state = MockState::default();
        state
            .insert(
                VALIDATOR_SET_KEY,
                &write_validator_sets(&validator_sets(&[(18, 1), (145, 1), (19, 1)])).unwrap(),
            )
            .unwrap();

        publish_recovered_publication_fixture(
            &registry,
            &mut state,
            &capsule_a,
            &certificates_a,
            &materials_a,
            &recovered_a,
        );
        publish_recovered_publication_fixture(
            &registry,
            &mut state,
            &capsule_b,
            &certificates_b,
            &materials_b,
            &recovered_b,
        );
        publish_recovered_publication_fixture(
            &registry,
            &mut state,
            &capsule_c,
            &certificates_c,
            &materials_c,
            &recovered_c,
        );
        publish_recovered_publication_fixture(
            &registry,
            &mut state,
            &capsule_d,
            &certificates_d,
            &materials_d,
            &recovered_d,
        );
        publish_recovered_publication_fixture(
            &registry,
            &mut state,
            &capsule_e,
            &certificates_e,
            &materials_e,
            &recovered_e,
        );
        with_ctx(|ctx| {
            for frontier in [&frontier_a, &frontier_c, &frontier_d, &frontier_e] {
                run_async(registry.handle_service_call(
                    &mut state,
                    "publish_aft_publication_frontier@v1",
                    &codec::to_bytes_canonical(frontier).unwrap(),
                    ctx,
                ))
                .unwrap();
            }
        });

        let slot_b_abort = GuardianRegistry::load_canonical_order_abort(&state, 2)
            .unwrap()
            .expect("slot-b omission should materialize an abort");
        let replay_prefix = GuardianRegistry::extract_canonical_replay_prefix(&state, 1, 5)
            .expect("extract canonical replay prefix");
        let expected_prefix = vec![
            canonical_replay_prefix_entry(
                &expected_collapse_a,
                Some(recovered_a.block_commitment_hash),
                Some(recovered_a.parent_block_commitment_hash),
                canonical_bulletin_close_hash(&close_a).expect("slot-a close hash"),
                Some(
                    canonical_publication_frontier_hash(&frontier_a)
                        .expect("slot-a publication frontier hash"),
                ),
                true,
            )
            .expect("slot-a replay prefix entry"),
            canonical_replay_prefix_entry(
                &expected_collapse_b,
                Some(recovered_b.block_commitment_hash),
                Some(recovered_b.parent_block_commitment_hash),
                canonical_order_abort_hash(&slot_b_abort).expect("slot-b abort hash"),
                None,
                false,
            )
            .expect("slot-b replay prefix entry"),
            canonical_replay_prefix_entry(
                &expected_collapse_c,
                Some(recovered_c.block_commitment_hash),
                Some(recovered_c.parent_block_commitment_hash),
                canonical_bulletin_close_hash(&close_c).expect("slot-c close hash"),
                Some(
                    canonical_publication_frontier_hash(&frontier_c)
                        .expect("slot-c publication frontier hash"),
                ),
                true,
            )
            .expect("slot-c replay prefix entry"),
            canonical_replay_prefix_entry(
                &expected_collapse_d,
                Some(recovered_d.block_commitment_hash),
                Some(recovered_d.parent_block_commitment_hash),
                canonical_bulletin_close_hash(&close_d).expect("slot-d close hash"),
                Some(
                    canonical_publication_frontier_hash(&frontier_d)
                        .expect("slot-d publication frontier hash"),
                ),
                true,
            )
            .expect("slot-d replay prefix entry"),
            canonical_replay_prefix_entry(
                &expected_collapse_e,
                Some(recovered_e.block_commitment_hash),
                Some(recovered_e.parent_block_commitment_hash),
                canonical_bulletin_close_hash(&close_e).expect("slot-e close hash"),
                Some(
                    canonical_publication_frontier_hash(&frontier_e)
                        .expect("slot-e publication frontier hash"),
                ),
                true,
            )
            .expect("slot-e replay prefix entry"),
        ];

        assert_eq!(replay_prefix, expected_prefix);
        assert_eq!(
            replay_prefix[0].resulting_state_root_hash,
            expected_collapse_a.resulting_state_root_hash
        );
        assert_eq!(
            replay_prefix[1].resulting_state_root_hash,
            expected_collapse_b.resulting_state_root_hash
        );
        assert_eq!(
            replay_prefix[2].resulting_state_root_hash,
            expected_collapse_c.resulting_state_root_hash
        );
        assert_eq!(
            replay_prefix[3].resulting_state_root_hash,
            expected_collapse_d.resulting_state_root_hash
        );
        assert_eq!(
            replay_prefix[4].resulting_state_root_hash,
            expected_collapse_e.resulting_state_root_hash
        );
        assert!(!replay_prefix[1].extracted_bulletin_surface_present);
        assert!(replay_prefix[0].extracted_bulletin_surface_present);
        assert!(replay_prefix[2].extracted_bulletin_surface_present);
        assert!(replay_prefix[3].extracted_bulletin_surface_present);
        assert!(replay_prefix[4].extracted_bulletin_surface_present);
        assert_eq!(
            replay_prefix[1].previous_canonical_collapse_commitment_hash,
            replay_prefix[0].canonical_collapse_commitment_hash
        );
        assert_eq!(
            replay_prefix[2].previous_canonical_collapse_commitment_hash,
            replay_prefix[1].canonical_collapse_commitment_hash
        );
        assert_eq!(
            replay_prefix[3].previous_canonical_collapse_commitment_hash,
            replay_prefix[2].canonical_collapse_commitment_hash
        );
        assert_eq!(
            replay_prefix[4].previous_canonical_collapse_commitment_hash,
            replay_prefix[3].canonical_collapse_commitment_hash
        );
        assert_eq!(
            replay_prefix[1].parent_block_commitment_hash,
            replay_prefix[0].canonical_block_commitment_hash
        );
        assert_eq!(
            replay_prefix[2].parent_block_commitment_hash,
            replay_prefix[1].canonical_block_commitment_hash
        );
        assert_eq!(
            replay_prefix[3].parent_block_commitment_hash,
            replay_prefix[2].canonical_block_commitment_hash
        );
        assert_eq!(
            replay_prefix[4].parent_block_commitment_hash,
            replay_prefix[3].canonical_block_commitment_hash
        );

        let recovered_header_prefix =
            GuardianRegistry::extract_recovered_canonical_header_prefix(&state, 1, 5)
                .expect("extract recovered canonical header prefix");
        let expected_header_prefix = vec![
            recovered_canonical_header_entry(&expected_collapse_a, &full_surface_a)
                .expect("slot-a recovered header entry"),
            recovered_canonical_header_entry(&expected_collapse_b, &full_surface_b)
                .expect("slot-b recovered header entry"),
            recovered_canonical_header_entry(&expected_collapse_c, &full_surface_c)
                .expect("slot-c recovered header entry"),
            recovered_canonical_header_entry(&expected_collapse_d, &full_surface_d)
                .expect("slot-d recovered header entry"),
            recovered_canonical_header_entry(&expected_collapse_e, &full_surface_e)
                .expect("slot-e recovered header entry"),
        ];

        assert_eq!(recovered_header_prefix, expected_header_prefix);
        assert_eq!(
            recovered_header_prefix[1].parent_block_commitment_hash,
            recovered_header_prefix[0].canonical_block_commitment_hash
        );
        assert_eq!(
            recovered_header_prefix[2].parent_block_commitment_hash,
            recovered_header_prefix[1].canonical_block_commitment_hash
        );
        assert_eq!(
            recovered_header_prefix[3].parent_block_commitment_hash,
            recovered_header_prefix[2].canonical_block_commitment_hash
        );
        assert_eq!(
            recovered_header_prefix[4].parent_block_commitment_hash,
            recovered_header_prefix[3].canonical_block_commitment_hash
        );

        let recovered_certified_prefix =
            GuardianRegistry::extract_recovered_certified_header_prefix(&state, 1, 5)
                .expect("extract recovered certified header prefix");
        let expected_certified_prefix =
            recovered_certified_header_prefix(None, &expected_header_prefix)
                .expect("expected recovered certified header prefix");
        assert_eq!(recovered_certified_prefix, expected_certified_prefix);
        assert_eq!(
            recovered_certified_prefix[1]
                .certified_parent_quorum_certificate
                .block_hash,
            recovered_header_prefix[0].canonical_block_commitment_hash
        );
        assert_eq!(
            recovered_certified_prefix[2].certified_parent_resulting_state_root_hash,
            recovered_header_prefix[1].resulting_state_root_hash
        );
        assert_eq!(
            recovered_certified_prefix[4]
                .certified_parent_quorum_certificate
                .block_hash,
            recovered_header_prefix[3].canonical_block_commitment_hash
        );
        assert_eq!(
            recovered_certified_prefix[4].certified_parent_resulting_state_root_hash,
            recovered_header_prefix[3].resulting_state_root_hash
        );

        let recovered_restart_prefix =
            GuardianRegistry::extract_recovered_restart_block_header_prefix(&state, 1, 5)
                .expect("extract recovered restart block-header prefix");
        let expected_restart_prefix = expected_certified_prefix
            .iter()
            .zip([
                &full_surface_a,
                &full_surface_b,
                &full_surface_c,
                &full_surface_d,
                &full_surface_e,
            ])
            .map(|(certified, full_surface)| {
                recovered_restart_block_header_entry(full_surface, certified)
                    .expect("expected recovered restart block-header entry")
            })
            .collect::<Vec<_>>();
        assert_eq!(recovered_restart_prefix, expected_restart_prefix);
        assert_eq!(
            recovered_restart_prefix[1].header.parent_qc,
            recovered_certified_prefix[1].certified_parent_quorum_certificate
        );
        assert_eq!(
            recovered_restart_prefix[2].header.parent_state_root.0,
            recovered_certified_prefix[2]
                .certified_parent_resulting_state_root_hash
                .to_vec()
        );
        assert_eq!(
            recovered_restart_prefix[3].header.parent_qc,
            recovered_restart_prefix[2].certified_quorum_certificate()
        );
        assert_eq!(
            recovered_restart_prefix[3].header.parent_state_root.0,
            recovered_certified_prefix[3]
                .certified_parent_resulting_state_root_hash
                .to_vec()
        );
        assert_eq!(
            recovered_restart_prefix[4].header.parent_qc,
            recovered_restart_prefix[3].certified_quorum_certificate()
        );
        assert_eq!(
            recovered_restart_prefix[4].header.parent_state_root.0,
            recovered_certified_prefix[4]
                .certified_parent_resulting_state_root_hash
                .to_vec()
        );

        let aft_recovered_state =
            GuardianRegistry::extract_aft_recovered_state_surface(&state, 1, 5)
                .expect("extract aft recovered state surface");
        assert_eq!(aft_recovered_state.replay_prefix, expected_prefix);
        assert_eq!(
            aft_recovered_state.consensus_headers,
            expected_header_prefix
        );
        assert_eq!(
            aft_recovered_state.certified_headers,
            expected_certified_prefix
        );
        assert_eq!(aft_recovered_state.restart_headers, expected_restart_prefix);
    }

    #[test]
    fn stitched_recovered_prefixes_match_direct_extract_for_overlapping_windows() {
        assert_stitched_recovered_prefixes_match_direct_extract(&[(1, 5), (4, 8)], 0x91, 8);
    }

    #[test]
    fn stitched_recovered_prefixes_match_direct_extract_for_three_overlapping_windows() {
        assert_stitched_recovered_prefixes_match_direct_extract(
            &[(1, 5), (4, 8), (7, 11)],
            0x71,
            11,
        );
    }

    #[test]
    fn stitched_recovered_prefixes_match_direct_extract_for_four_overlapping_windows() {
        assert_stitched_recovered_prefixes_match_direct_extract(
            &[(1, 5), (4, 8), (7, 11), (10, 14)],
            0x51,
            14,
        );
    }

    #[test]
    fn stitched_recovered_prefixes_match_direct_extract_for_five_overlapping_windows() {
        assert_stitched_recovered_prefixes_match_direct_extract(
            &[(1, 5), (4, 8), (7, 11), (10, 14), (13, 17)],
            0x31,
            17,
        );
    }

    #[test]
    fn aft_recovered_state_surface_matches_legacy_extractors_across_supported_coded_families() {
        for (coding, support_share_indices, seed_base) in [
            (xor_recovery_coding(3, 2), vec![0, 2], 0x31),
            (xor_recovery_coding(4, 3), vec![0, 2, 3], 0x41),
            (gf256_recovery_coding(4, 2), vec![1, 3], 0x51),
            (gf256_recovery_coding(7, 3), vec![0, 3, 6], 0x61),
            (gf256_recovery_coding(7, 4), vec![0, 2, 4, 6], 0x71),
        ] {
            assert_aft_recovered_state_surface_matches_legacy_extractors_for_coding(
                coding,
                &support_share_indices,
                seed_base,
            );
        }
    }

    #[test]
    fn stitched_recovered_prefix_segments_match_direct_extract_for_two_overlapping_five_window_segments(
    ) {
        let first_segment = [(1, 5), (4, 8), (7, 11), (10, 14), (13, 17)];
        let second_segment = [(13, 17), (16, 20), (19, 23), (22, 26), (25, 29)];
        assert_segment_stitched_recovered_prefixes_match_direct_extract(
            &[first_segment.as_slice(), second_segment.as_slice()],
            0x11,
            29,
        );
    }

    #[test]
    fn stitched_recovered_prefix_segments_match_direct_extract_for_three_overlapping_five_window_segments(
    ) {
        let first_segment = [(1, 5), (4, 8), (7, 11), (10, 14), (13, 17)];
        let second_segment = [(13, 17), (16, 20), (19, 23), (22, 26), (25, 29)];
        let third_segment = [(25, 29), (28, 32), (31, 35), (34, 38), (37, 41)];
        assert_segment_stitched_recovered_prefixes_match_direct_extract(
            &[
                first_segment.as_slice(),
                second_segment.as_slice(),
                third_segment.as_slice(),
            ],
            0x01,
            41,
        );
    }

    #[test]
    fn stitched_recovered_prefix_segments_match_direct_extract_for_four_overlapping_five_window_segments(
    ) {
        let first_segment = [(1, 5), (4, 8), (7, 11), (10, 14), (13, 17)];
        let second_segment = [(13, 17), (16, 20), (19, 23), (22, 26), (25, 29)];
        let third_segment = [(25, 29), (28, 32), (31, 35), (34, 38), (37, 41)];
        let fourth_segment = [(37, 41), (40, 44), (43, 47), (46, 50), (49, 53)];
        assert_segment_stitched_recovered_prefixes_match_direct_extract(
            &[
                first_segment.as_slice(),
                second_segment.as_slice(),
                third_segment.as_slice(),
                fourth_segment.as_slice(),
            ],
            0x21,
            53,
        );
    }

    #[test]
    fn stitched_recovered_prefix_segment_folds_match_direct_extract_for_two_overlapping_four_segment_folds(
    ) {
        let first_fold = vec![
            vec![(1, 5), (4, 8), (7, 11), (10, 14), (13, 17)],
            vec![(13, 17), (16, 20), (19, 23), (22, 26), (25, 29)],
            vec![(25, 29), (28, 32), (31, 35), (34, 38), (37, 41)],
            vec![(37, 41), (40, 44), (43, 47), (46, 50), (49, 53)],
        ];
        let second_fold = vec![
            vec![(37, 41), (40, 44), (43, 47), (46, 50), (49, 53)],
            vec![(49, 53), (52, 56), (55, 59), (58, 62), (61, 65)],
            vec![(61, 65), (64, 68), (67, 71), (70, 74), (73, 77)],
            vec![(73, 77), (76, 80), (79, 83), (82, 86), (85, 89)],
        ];
        assert_segment_fold_stitched_recovered_prefixes_match_direct_extract(
            &[first_fold, second_fold],
            0x41,
            89,
        );
    }

    #[test]
    fn stitched_recovered_prefix_segment_folds_match_direct_extract_for_three_overlapping_four_segment_folds(
    ) {
        let first_fold = vec![
            vec![(1, 5), (4, 8), (7, 11), (10, 14), (13, 17)],
            vec![(13, 17), (16, 20), (19, 23), (22, 26), (25, 29)],
            vec![(25, 29), (28, 32), (31, 35), (34, 38), (37, 41)],
            vec![(37, 41), (40, 44), (43, 47), (46, 50), (49, 53)],
        ];
        let second_fold = vec![
            vec![(37, 41), (40, 44), (43, 47), (46, 50), (49, 53)],
            vec![(49, 53), (52, 56), (55, 59), (58, 62), (61, 65)],
            vec![(61, 65), (64, 68), (67, 71), (70, 74), (73, 77)],
            vec![(73, 77), (76, 80), (79, 83), (82, 86), (85, 89)],
        ];
        let third_fold = vec![
            vec![(73, 77), (76, 80), (79, 83), (82, 86), (85, 89)],
            vec![(85, 89), (88, 92), (91, 95), (94, 98), (97, 101)],
            vec![(97, 101), (100, 104), (103, 107), (106, 110), (109, 113)],
            vec![(109, 113), (112, 116), (115, 119), (118, 122), (121, 125)],
        ];
        assert_segment_fold_stitched_recovered_prefixes_match_direct_extract(
            &[first_fold, second_fold, third_fold],
            0x51,
            125,
        );
    }

    #[test]
    fn stitched_recovered_prefix_segment_folds_match_direct_extract_across_fold_budgets() {
        let cases = [
            (
                vec![vec![
                    vec![(1, 5), (4, 8), (7, 11), (10, 14), (13, 17)],
                    vec![(13, 17), (16, 20), (19, 23), (22, 26), (25, 29)],
                    vec![(25, 29), (28, 32), (31, 35), (34, 38), (37, 41)],
                    vec![(37, 41), (40, 44), (43, 47), (46, 50), (49, 53)],
                ]],
                0x21,
                53u64,
            ),
            (
                vec![
                    vec![
                        vec![(1, 5), (4, 8), (7, 11), (10, 14), (13, 17)],
                        vec![(13, 17), (16, 20), (19, 23), (22, 26), (25, 29)],
                        vec![(25, 29), (28, 32), (31, 35), (34, 38), (37, 41)],
                        vec![(37, 41), (40, 44), (43, 47), (46, 50), (49, 53)],
                    ],
                    vec![
                        vec![(37, 41), (40, 44), (43, 47), (46, 50), (49, 53)],
                        vec![(49, 53), (52, 56), (55, 59), (58, 62), (61, 65)],
                        vec![(61, 65), (64, 68), (67, 71), (70, 74), (73, 77)],
                        vec![(73, 77), (76, 80), (79, 83), (82, 86), (85, 89)],
                    ],
                ],
                0x41,
                89u64,
            ),
            (
                vec![
                    vec![
                        vec![(1, 5), (4, 8), (7, 11), (10, 14), (13, 17)],
                        vec![(13, 17), (16, 20), (19, 23), (22, 26), (25, 29)],
                        vec![(25, 29), (28, 32), (31, 35), (34, 38), (37, 41)],
                        vec![(37, 41), (40, 44), (43, 47), (46, 50), (49, 53)],
                    ],
                    vec![
                        vec![(37, 41), (40, 44), (43, 47), (46, 50), (49, 53)],
                        vec![(49, 53), (52, 56), (55, 59), (58, 62), (61, 65)],
                        vec![(61, 65), (64, 68), (67, 71), (70, 74), (73, 77)],
                        vec![(73, 77), (76, 80), (79, 83), (82, 86), (85, 89)],
                    ],
                    vec![
                        vec![(73, 77), (76, 80), (79, 83), (82, 86), (85, 89)],
                        vec![(85, 89), (88, 92), (91, 95), (94, 98), (97, 101)],
                        vec![(97, 101), (100, 104), (103, 107), (106, 110), (109, 113)],
                        vec![(109, 113), (112, 116), (115, 119), (118, 122), (121, 125)],
                    ],
                ],
                0x51,
                125u64,
            ),
        ];

        for (segment_folds, seed_base, expected_end_height) in cases {
            assert_segment_fold_stitched_recovered_prefixes_match_direct_extract(
                &segment_folds,
                seed_base,
                expected_end_height,
            );
        }
    }

    #[test]
    fn paged_recovered_prefixes_match_direct_extract_for_two_hundred_thirty_three_step_branch() {
        assert_paged_recovered_prefixes_match_direct_extract(0x61, 233);
    }

    #[test]
    fn paged_recovered_prefixes_match_direct_extract_across_page_depths() {
        for (index, expected_end_height) in [89u64, 125, 161, 197, 233].into_iter().enumerate() {
            assert_paged_recovered_prefixes_match_direct_extract(
                0x70u8.wrapping_add(index as u8),
                expected_end_height,
            );
        }
    }

    #[test]
    fn extract_recovered_prefix_page_rejects_missing_gap_page() {
        let (_registry, mut state) = build_recovered_registry_state(0x63, 233);
        let mut cursor = RecoveredSegmentFoldCursor::new(233, 5, 2, 5, 4, 2)
            .expect("recovered segment-fold cursor");
        let page = cursor
            .next_page()
            .expect("advance recovered segment-fold cursor")
            .expect("older recovered page");
        let gap_height = page.start_height + 7;
        let recovered_prefix = [
            AFT_RECOVERED_PUBLICATION_BUNDLE_PREFIX,
            &gap_height.to_be_bytes(),
        ]
        .concat();
        state
            .data
            .retain(|key, _| !key.starts_with(&recovered_prefix));

        let error = GuardianRegistry::extract_recovered_restart_block_header_page(&state, &page)
            .expect_err("missing recovered page gap must fail");
        let message = error.to_string();
        assert!(
            (message.contains("expected") && message.contains("loaded"))
                || message.contains("must be consecutive")
                || message.contains("requires a unique recovered publication bundle"),
            "unexpected missing-page error: {message}"
        );
    }

    fn bounded_recovered_window_ranges(
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

    fn bounded_recovered_segment_ranges(
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

    fn bounded_recovered_segment_fold_start_height(
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

    fn build_recovered_registry_state(
        seed_base: u8,
        expected_end_height: u64,
    ) -> (GuardianRegistry, MockState) {
        let registry = production_registry_without_accountable_membership_updates();
        let mut state = MockState::default();
        state
            .insert(
                VALIDATOR_SET_KEY,
                &write_validator_sets(&validator_sets(&[(18, 1), (145, 1), (19, 1)])).unwrap(),
            )
            .unwrap();

        let mut parent_block_hash = None;
        for (offset, height) in (1u64..=expected_end_height).enumerate() {
            let seed = seed_base.wrapping_add(offset as u8);
            let (capsule, certificates, materials, recovered) =
                if let Some(parent_block_hash) = parent_block_hash {
                    sample_recovered_publication_bundle_fixture_3_of_7_with_parent(
                        height,
                        seed,
                        parent_block_hash,
                    )
                } else {
                    sample_recovered_publication_bundle_fixture_3_of_7(height, seed)
                };
            parent_block_hash = Some(recovered.block_commitment_hash);
            publish_recovered_publication_fixture(
                &registry,
                &mut state,
                &capsule,
                &certificates,
                &materials,
                &recovered,
            );
        }

        (registry, state)
    }

    fn assert_paged_recovered_prefixes_match_direct_extract(
        seed_base: u8,
        expected_end_height: u64,
    ) {
        let (_registry, state) = build_recovered_registry_state(seed_base, expected_end_height);
        let direct_certified = GuardianRegistry::extract_recovered_certified_header_prefix(
            &state,
            1,
            expected_end_height,
        )
        .expect("direct recovered certified-header prefix");
        let direct_restart = GuardianRegistry::extract_recovered_restart_block_header_prefix(
            &state,
            1,
            expected_end_height,
        )
        .expect("direct recovered restart block-header prefix");

        let start_height =
            bounded_recovered_segment_fold_start_height(expected_end_height, 5, 2, 5, 4, 2);
        let initial_segments =
            bounded_recovered_segment_ranges(start_height, expected_end_height, 5, 2, 5);
        let initial_segment_slices = initial_segments
            .iter()
            .map(Vec::as_slice)
            .collect::<Vec<_>>();
        let mut stitched_certified =
            GuardianRegistry::extract_stitched_recovered_certified_header_segments(
                &state,
                &initial_segment_slices,
            )
            .expect("initial stitched recovered certified-header prefix");
        let mut stitched_restart =
            GuardianRegistry::extract_stitched_recovered_restart_block_header_segments(
                &state,
                &initial_segment_slices,
            )
            .expect("initial stitched recovered restart block-header prefix");
        let mut cursor = RecoveredSegmentFoldCursor::new(expected_end_height, 5, 2, 5, 4, 2)
            .expect("recovered segment-fold cursor");

        while stitched_restart
            .first()
            .map(|entry| entry.header.height)
            .unwrap_or(u64::MAX)
            > 1
        {
            let page = cursor
                .next_page()
                .expect("advance recovered segment-fold cursor")
                .expect("older recovered page");
            let page_certified =
                GuardianRegistry::extract_recovered_certified_header_page(&state, &page)
                    .expect("paged recovered certified-header prefix");
            let page_restart =
                GuardianRegistry::extract_recovered_restart_block_header_page(&state, &page)
                    .expect("paged recovered restart block-header prefix");
            stitched_certified = stitch_recovered_certified_header_segments(&[
                page_certified.as_slice(),
                stitched_certified.as_slice(),
            ])
            .expect("stitch paged recovered certified-header prefixes");
            stitched_restart = stitch_recovered_restart_block_header_segments(&[
                page_restart.as_slice(),
                stitched_restart.as_slice(),
            ])
            .expect("stitch paged recovered restart block-header prefixes");
        }

        assert_eq!(stitched_certified, direct_certified);
        assert_eq!(stitched_restart, direct_restart);
        assert_eq!(stitched_certified.len(), expected_end_height as usize);
        assert_eq!(stitched_restart.len(), expected_end_height as usize);
    }

    fn assert_stitched_recovered_prefixes_match_direct_extract(
        windows: &[(u64, u64)],
        seed_base: u8,
        expected_end_height: u64,
    ) {
        let registry = production_registry_without_accountable_membership_updates();
        let mut state = MockState::default();
        state
            .insert(
                VALIDATOR_SET_KEY,
                &write_validator_sets(&validator_sets(&[(18, 1), (145, 1), (19, 1)])).unwrap(),
            )
            .unwrap();

        let mut parent_block_hash = None;
        for (offset, height) in (1u64..=expected_end_height).enumerate() {
            let seed = seed_base.wrapping_add(offset as u8);
            let (capsule, certificates, materials, recovered) =
                if let Some(parent_block_hash) = parent_block_hash {
                    sample_recovered_publication_bundle_fixture_3_of_7_with_parent(
                        height,
                        seed,
                        parent_block_hash,
                    )
                } else {
                    sample_recovered_publication_bundle_fixture_3_of_7(height, seed)
                };
            parent_block_hash = Some(recovered.block_commitment_hash);
            publish_recovered_publication_fixture(
                &registry,
                &mut state,
                &capsule,
                &certificates,
                &materials,
                &recovered,
            );
        }

        let direct_certified = GuardianRegistry::extract_recovered_certified_header_prefix(
            &state,
            1,
            expected_end_height,
        )
        .expect("direct recovered certified-header prefix");
        let stitched_certified =
            GuardianRegistry::extract_stitched_recovered_certified_header_prefix(&state, windows)
                .expect("stitched recovered certified-header prefix");
        assert_eq!(stitched_certified, direct_certified);
        assert_eq!(stitched_certified.len(), expected_end_height as usize);

        let direct_restart = GuardianRegistry::extract_recovered_restart_block_header_prefix(
            &state,
            1,
            expected_end_height,
        )
        .expect("direct recovered restart block-header prefix");
        let stitched_restart =
            GuardianRegistry::extract_stitched_recovered_restart_block_header_prefix(
                &state, windows,
            )
            .expect("stitched recovered restart block-header prefix");
        assert_eq!(stitched_restart, direct_restart);
        assert_eq!(stitched_restart.len(), expected_end_height as usize);
        let tail_index = stitched_restart.len() - 1;
        assert_eq!(
            stitched_restart[tail_index].header.parent_qc,
            stitched_restart[tail_index - 1].certified_quorum_certificate()
        );
    }

    fn assert_aft_recovered_state_surface_matches_legacy_extractors_for_coding(
        coding: RecoveryCodingDescriptor,
        support_share_indices: &[u16],
        seed_base: u8,
    ) {
        let registry = production_registry_without_accountable_membership_updates();
        let mut state = MockState::default();
        state
            .insert(
                VALIDATOR_SET_KEY,
                &write_validator_sets(&validator_sets(&[(18, 1), (145, 1), (19, 1)])).unwrap(),
            )
            .unwrap();

        let (capsule_a, certificates_a, materials_a, recovered_a) =
            sample_recovered_publication_bundle_fixture_with_scheme(
                1,
                seed_base,
                coding,
                support_share_indices,
            );
        let (capsule_b, certificates_b, materials_b, recovered_b) =
            sample_recovered_publication_bundle_fixture_with_scheme_and_optional_omission(
                2,
                seed_base.wrapping_add(1),
                coding,
                support_share_indices,
                Some(recovered_a.block_commitment_hash),
                None,
            );
        publish_recovered_publication_fixture(
            &registry,
            &mut state,
            &capsule_a,
            &certificates_a,
            &materials_a,
            &recovered_a,
        );
        publish_recovered_publication_fixture(
            &registry,
            &mut state,
            &capsule_b,
            &certificates_b,
            &materials_b,
            &recovered_b,
        );

        let aft_state = GuardianRegistry::extract_aft_recovered_state_surface(&state, 1, 2)
            .expect("extract aft recovered state surface");
        assert_eq!(
            aft_state.replay_prefix,
            GuardianRegistry::extract_aft_recovered_replay_prefix(&state, 1, 2)
                .expect("extract replay prefix")
        );
        assert_eq!(
            aft_state.consensus_headers,
            GuardianRegistry::extract_aft_recovered_consensus_header_prefix(&state, 1, 2)
                .expect("extract consensus-header prefix")
        );
        assert_eq!(
            aft_state.certified_headers,
            GuardianRegistry::extract_aft_recovered_certified_header_prefix(&state, 1, 2)
                .expect("extract certified-header prefix")
        );
        assert_eq!(
            aft_state.restart_headers,
            GuardianRegistry::extract_aft_recovered_restart_header_prefix(&state, 1, 2)
                .expect("extract restart-header prefix")
        );
        assert_eq!(
            aft_state.restart_headers[1].header.parent_qc,
            aft_state.certified_headers[1].certified_parent_quorum_certificate
        );
    }

    fn assert_segment_stitched_recovered_prefixes_match_direct_extract(
        segments: &[&[(u64, u64)]],
        seed_base: u8,
        expected_end_height: u64,
    ) {
        let registry = production_registry_without_accountable_membership_updates();
        let mut state = MockState::default();
        state
            .insert(
                VALIDATOR_SET_KEY,
                &write_validator_sets(&validator_sets(&[(18, 1), (145, 1), (19, 1)])).unwrap(),
            )
            .unwrap();

        let mut parent_block_hash = None;
        for (offset, height) in (1u64..=expected_end_height).enumerate() {
            let seed = seed_base.wrapping_add(offset as u8);
            let (capsule, certificates, materials, recovered) =
                if let Some(parent_block_hash) = parent_block_hash {
                    sample_recovered_publication_bundle_fixture_3_of_7_with_parent(
                        height,
                        seed,
                        parent_block_hash,
                    )
                } else {
                    sample_recovered_publication_bundle_fixture_3_of_7(height, seed)
                };
            parent_block_hash = Some(recovered.block_commitment_hash);
            publish_recovered_publication_fixture(
                &registry,
                &mut state,
                &capsule,
                &certificates,
                &materials,
                &recovered,
            );
        }

        let direct_certified = GuardianRegistry::extract_recovered_certified_header_prefix(
            &state,
            1,
            expected_end_height,
        )
        .expect("direct recovered certified-header prefix");
        let stitched_certified =
            GuardianRegistry::extract_stitched_recovered_certified_header_segments(
                &state, segments,
            )
            .expect("segment-stitched recovered certified-header prefix");
        assert_eq!(stitched_certified, direct_certified);
        assert_eq!(stitched_certified.len(), expected_end_height as usize);

        let direct_restart = GuardianRegistry::extract_recovered_restart_block_header_prefix(
            &state,
            1,
            expected_end_height,
        )
        .expect("direct recovered restart block-header prefix");
        let stitched_restart =
            GuardianRegistry::extract_stitched_recovered_restart_block_header_segments(
                &state, segments,
            )
            .expect("segment-stitched recovered restart block-header prefix");
        assert_eq!(stitched_restart, direct_restart);
        assert_eq!(stitched_restart.len(), expected_end_height as usize);
        let tail_index = stitched_restart.len() - 1;
        assert_eq!(
            stitched_restart[tail_index].header.parent_qc,
            stitched_restart[tail_index - 1].certified_quorum_certificate()
        );
    }

    fn assert_segment_fold_stitched_recovered_prefixes_match_direct_extract(
        segment_folds: &[Vec<Vec<(u64, u64)>>],
        seed_base: u8,
        expected_end_height: u64,
    ) {
        let registry = production_registry_without_accountable_membership_updates();
        let mut state = MockState::default();
        state
            .insert(
                VALIDATOR_SET_KEY,
                &write_validator_sets(&validator_sets(&[(18, 1), (145, 1), (19, 1)])).unwrap(),
            )
            .unwrap();

        let mut parent_block_hash = None;
        for (offset, height) in (1u64..=expected_end_height).enumerate() {
            let seed = seed_base.wrapping_add(offset as u8);
            let (capsule, certificates, materials, recovered) =
                if let Some(parent_block_hash) = parent_block_hash {
                    sample_recovered_publication_bundle_fixture_3_of_7_with_parent(
                        height,
                        seed,
                        parent_block_hash,
                    )
                } else {
                    sample_recovered_publication_bundle_fixture_3_of_7(height, seed)
                };
            parent_block_hash = Some(recovered.block_commitment_hash);
            publish_recovered_publication_fixture(
                &registry,
                &mut state,
                &capsule,
                &certificates,
                &materials,
                &recovered,
            );
        }

        let direct_certified = GuardianRegistry::extract_recovered_certified_header_prefix(
            &state,
            1,
            expected_end_height,
        )
        .expect("direct recovered certified-header prefix");
        let stitched_certified =
            GuardianRegistry::extract_stitched_recovered_certified_header_segment_folds(
                &state,
                segment_folds,
            )
            .expect("segment-fold-stitched recovered certified-header prefix");
        assert_eq!(stitched_certified, direct_certified);
        assert_eq!(stitched_certified.len(), expected_end_height as usize);

        let direct_restart = GuardianRegistry::extract_recovered_restart_block_header_prefix(
            &state,
            1,
            expected_end_height,
        )
        .expect("direct recovered restart block-header prefix");
        let stitched_restart =
            GuardianRegistry::extract_stitched_recovered_restart_block_header_segment_folds(
                &state,
                segment_folds,
            )
            .expect("segment-fold-stitched recovered restart block-header prefix");
        assert_eq!(stitched_restart, direct_restart);
        assert_eq!(stitched_restart.len(), expected_end_height as usize);
        let tail_index = stitched_restart.len() - 1;
        assert_eq!(
            stitched_restart[tail_index].header.parent_qc,
            stitched_restart[tail_index - 1].certified_quorum_certificate()
        );
    }

    #[test]
    fn publishing_recovered_publication_bundle_rejects_tampered_full_surface_hash() {
        let registry = production_registry();
        let (capsule, certificates, materials, mut recovered) =
            sample_recovered_publication_bundle_fixture(80, 91);
        recovered.recoverable_full_surface_hash[0] ^= 0xFF;

        let mut state = MockState::default();
        seed_previous_canonical_collapse_placeholder_if_absent(&mut state, recovered.height, 0x91);
        let mut publish_error = None;
        with_ctx(|ctx| {
            run_async(registry.handle_service_call(
                &mut state,
                "publish_aft_recovery_capsule@v1",
                &codec::to_bytes_canonical(&capsule).unwrap(),
                ctx,
            ))
            .unwrap();
            for certificate in &certificates {
                run_async(registry.handle_service_call(
                    &mut state,
                    "publish_aft_recovery_witness_certificate@v1",
                    &codec::to_bytes_canonical(certificate).unwrap(),
                    ctx,
                ))
                .unwrap();
            }
            for material in &materials {
                let receipt = material.to_recovery_share_receipt();
                run_async(registry.handle_service_call(
                    &mut state,
                    "publish_aft_recovery_share_receipt@v1",
                    &codec::to_bytes_canonical(&receipt).unwrap(),
                    ctx,
                ))
                .unwrap();
                run_async(registry.handle_service_call(
                    &mut state,
                    "publish_aft_recovery_share_material@v1",
                    &codec::to_bytes_canonical(material).unwrap(),
                    ctx,
                ))
                .unwrap();
            }
            publish_error = Some(
                run_async(registry.handle_service_call(
                    &mut state,
                    "publish_aft_recovered_publication_bundle@v1",
                    &codec::to_bytes_canonical(&recovered).unwrap(),
                    ctx,
                ))
                .unwrap_err(),
            );
        });
        let error = publish_error.expect("tampered recovered publication bundle should fail");

        assert!(
            error.to_string().contains("full extractable surface hash"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn publishing_recovered_publication_bundle_round_trips_after_three_public_reveals() {
        let registry = production_registry();
        let (capsule, certificates, materials, recovered) =
            sample_recovered_publication_bundle_fixture_3_of_5(80, 120);
        let (_, expected_bundle) =
            recover_canonical_order_publication_bundle_from_share_materials(&materials)
                .expect("reconstruct recovered publication bundle");
        let expected_close = build_canonical_bulletin_close(
            &expected_bundle.bulletin_commitment,
            &expected_bundle.bulletin_availability_certificate,
        )
        .expect("canonical bulletin close");
        let mut expected_surface = expected_bundle.bulletin_entries.clone();
        expected_surface.sort_unstable_by(|left, right| left.tx_hash.cmp(&right.tx_hash));

        let mut state = MockState::default();
        seed_previous_canonical_collapse_placeholder_if_absent(&mut state, recovered.height, 0x92);
        with_ctx(|ctx| {
            run_async(registry.handle_service_call(
                &mut state,
                "publish_aft_recovery_capsule@v1",
                &codec::to_bytes_canonical(&capsule).unwrap(),
                ctx,
            ))
            .unwrap();
            for certificate in &certificates {
                run_async(registry.handle_service_call(
                    &mut state,
                    "publish_aft_recovery_witness_certificate@v1",
                    &codec::to_bytes_canonical(certificate).unwrap(),
                    ctx,
                ))
                .unwrap();
            }
            for material in &materials {
                let receipt = material.to_recovery_share_receipt();
                run_async(registry.handle_service_call(
                    &mut state,
                    "publish_aft_recovery_share_receipt@v1",
                    &codec::to_bytes_canonical(&receipt).unwrap(),
                    ctx,
                ))
                .unwrap();
                run_async(registry.handle_service_call(
                    &mut state,
                    "publish_aft_recovery_share_material@v1",
                    &codec::to_bytes_canonical(material).unwrap(),
                    ctx,
                ))
                .unwrap();
            }
            run_async(registry.handle_service_call(
                &mut state,
                "publish_aft_recovered_publication_bundle@v1",
                &codec::to_bytes_canonical(&recovered).unwrap(),
                ctx,
            ))
            .unwrap();
        });

        assert_eq!(
            GuardianRegistry::load_bulletin_commitment(&state, recovered.height).unwrap(),
            Some(expected_bundle.bulletin_commitment.clone())
        );
        assert_eq!(
            GuardianRegistry::load_bulletin_availability_certificate(&state, recovered.height)
                .unwrap(),
            Some(expected_bundle.bulletin_availability_certificate.clone())
        );
        assert_eq!(
            GuardianRegistry::load_canonical_bulletin_close(&state, recovered.height).unwrap(),
            Some(expected_close)
        );
        assert_eq!(
            recovered.canonical_bulletin_close_hash,
            canonical_bulletin_close_hash(
                &GuardianRegistry::load_canonical_bulletin_close(&state, recovered.height)
                    .unwrap()
                    .expect("persisted bulletin close"),
            )
            .expect("persisted bulletin close hash")
        );
        assert_eq!(
            GuardianRegistry::extract_published_bulletin_surface(&state, recovered.height).unwrap(),
            Some(expected_surface)
        );
        assert_eq!(
            GuardianRegistry::load_recovered_publication_bundles(
                &state,
                recovered.height,
                &recovered.block_commitment_hash,
            )
            .unwrap(),
            vec![recovered.clone()]
        );
        assert!(state
            .get(
                &aft_recovered_publication_bundle_key(
                    recovered.height,
                    &recovered.block_commitment_hash,
                    &recovered.supporting_witness_manifest_hashes,
                )
                .unwrap(),
            )
            .unwrap()
            .is_some());
    }

    #[test]
    fn publishing_recovered_publication_bundle_round_trips_after_three_of_seven_public_reveals() {
        let registry = production_registry();
        let (capsule, certificates, materials, recovered) =
            sample_recovered_publication_bundle_fixture_3_of_7(80, 130);
        let (_, expected_bundle) =
            recover_canonical_order_publication_bundle_from_share_materials(&materials)
                .expect("reconstruct recovered publication bundle");
        let expected_close = build_canonical_bulletin_close(
            &expected_bundle.bulletin_commitment,
            &expected_bundle.bulletin_availability_certificate,
        )
        .expect("canonical bulletin close");
        let mut expected_surface = expected_bundle.bulletin_entries.clone();
        expected_surface.sort_unstable_by(|left, right| left.tx_hash.cmp(&right.tx_hash));

        let mut state = MockState::default();
        seed_previous_canonical_collapse_placeholder_if_absent(&mut state, recovered.height, 0x93);
        with_ctx(|ctx| {
            run_async(registry.handle_service_call(
                &mut state,
                "publish_aft_recovery_capsule@v1",
                &codec::to_bytes_canonical(&capsule).unwrap(),
                ctx,
            ))
            .unwrap();
            for certificate in &certificates {
                run_async(registry.handle_service_call(
                    &mut state,
                    "publish_aft_recovery_witness_certificate@v1",
                    &codec::to_bytes_canonical(certificate).unwrap(),
                    ctx,
                ))
                .unwrap();
            }
            for material in &materials {
                let receipt = material.to_recovery_share_receipt();
                run_async(registry.handle_service_call(
                    &mut state,
                    "publish_aft_recovery_share_receipt@v1",
                    &codec::to_bytes_canonical(&receipt).unwrap(),
                    ctx,
                ))
                .unwrap();
                run_async(registry.handle_service_call(
                    &mut state,
                    "publish_aft_recovery_share_material@v1",
                    &codec::to_bytes_canonical(material).unwrap(),
                    ctx,
                ))
                .unwrap();
            }
            run_async(registry.handle_service_call(
                &mut state,
                "publish_aft_recovered_publication_bundle@v1",
                &codec::to_bytes_canonical(&recovered).unwrap(),
                ctx,
            ))
            .unwrap();
        });

        assert_eq!(
            GuardianRegistry::load_bulletin_commitment(&state, recovered.height).unwrap(),
            Some(expected_bundle.bulletin_commitment.clone())
        );
        assert_eq!(
            GuardianRegistry::load_bulletin_availability_certificate(&state, recovered.height)
                .unwrap(),
            Some(expected_bundle.bulletin_availability_certificate.clone())
        );
        assert_eq!(
            GuardianRegistry::load_canonical_bulletin_close(&state, recovered.height).unwrap(),
            Some(expected_close)
        );
        assert_eq!(
            GuardianRegistry::extract_published_bulletin_surface(&state, recovered.height).unwrap(),
            Some(expected_surface)
        );
        assert_eq!(
            GuardianRegistry::load_recovered_publication_bundles(
                &state,
                recovered.height,
                &recovered.block_commitment_hash,
            )
            .unwrap(),
            vec![recovered.clone()]
        );
        assert!(state
            .get(
                &aft_recovered_publication_bundle_key(
                    recovered.height,
                    &recovered.block_commitment_hash,
                    &recovered.supporting_witness_manifest_hashes,
                )
                .unwrap(),
            )
            .unwrap()
            .is_some());
    }

    #[test]
    fn publishing_recovered_publication_bundle_round_trips_after_four_public_reveals() {
        let registry = production_registry();
        let (capsule, certificates, materials, recovered) =
            sample_recovered_publication_bundle_fixture_4_of_6(80, 140);
        let (_, expected_bundle) =
            recover_canonical_order_publication_bundle_from_share_materials(&materials)
                .expect("reconstruct recovered publication bundle");
        let expected_close = build_canonical_bulletin_close(
            &expected_bundle.bulletin_commitment,
            &expected_bundle.bulletin_availability_certificate,
        )
        .expect("canonical bulletin close");
        let mut expected_surface = expected_bundle.bulletin_entries.clone();
        expected_surface.sort_unstable_by(|left, right| left.tx_hash.cmp(&right.tx_hash));

        let mut state = MockState::default();
        seed_previous_canonical_collapse_placeholder_if_absent(&mut state, recovered.height, 0x94);
        with_ctx(|ctx| {
            run_async(registry.handle_service_call(
                &mut state,
                "publish_aft_recovery_capsule@v1",
                &codec::to_bytes_canonical(&capsule).unwrap(),
                ctx,
            ))
            .unwrap();
            for certificate in &certificates {
                run_async(registry.handle_service_call(
                    &mut state,
                    "publish_aft_recovery_witness_certificate@v1",
                    &codec::to_bytes_canonical(certificate).unwrap(),
                    ctx,
                ))
                .unwrap();
            }
            for material in &materials {
                let receipt = material.to_recovery_share_receipt();
                run_async(registry.handle_service_call(
                    &mut state,
                    "publish_aft_recovery_share_receipt@v1",
                    &codec::to_bytes_canonical(&receipt).unwrap(),
                    ctx,
                ))
                .unwrap();
                run_async(registry.handle_service_call(
                    &mut state,
                    "publish_aft_recovery_share_material@v1",
                    &codec::to_bytes_canonical(material).unwrap(),
                    ctx,
                ))
                .unwrap();
            }
            run_async(registry.handle_service_call(
                &mut state,
                "publish_aft_recovered_publication_bundle@v1",
                &codec::to_bytes_canonical(&recovered).unwrap(),
                ctx,
            ))
            .unwrap();
        });

        assert_eq!(
            GuardianRegistry::load_bulletin_commitment(&state, recovered.height).unwrap(),
            Some(expected_bundle.bulletin_commitment.clone())
        );
        assert_eq!(
            GuardianRegistry::load_bulletin_availability_certificate(&state, recovered.height)
                .unwrap(),
            Some(expected_bundle.bulletin_availability_certificate.clone())
        );
        assert_eq!(
            GuardianRegistry::load_canonical_bulletin_close(&state, recovered.height).unwrap(),
            Some(expected_close)
        );
        assert_eq!(
            GuardianRegistry::extract_published_bulletin_surface(&state, recovered.height).unwrap(),
            Some(expected_surface)
        );
        assert_eq!(
            GuardianRegistry::load_recovered_publication_bundles(
                &state,
                recovered.height,
                &recovered.block_commitment_hash,
            )
            .unwrap(),
            vec![recovered.clone()]
        );
        assert!(state
            .get(
                &aft_recovered_publication_bundle_key(
                    recovered.height,
                    &recovered.block_commitment_hash,
                    &recovered.supporting_witness_manifest_hashes,
                )
                .unwrap(),
            )
            .unwrap()
            .is_some());
    }

    #[test]
    fn publishing_recovered_publication_bundle_round_trips_after_four_of_seven_public_reveals() {
        let registry = production_registry();
        let (capsule, certificates, materials, recovered) =
            sample_recovered_publication_bundle_fixture_4_of_7(81, 150);
        let (_, expected_bundle) =
            recover_canonical_order_publication_bundle_from_share_materials(&materials)
                .expect("reconstruct recovered publication bundle");
        let expected_close = build_canonical_bulletin_close(
            &expected_bundle.bulletin_commitment,
            &expected_bundle.bulletin_availability_certificate,
        )
        .expect("canonical bulletin close");
        let mut expected_surface = expected_bundle.bulletin_entries.clone();
        expected_surface.sort_unstable_by(|left, right| left.tx_hash.cmp(&right.tx_hash));

        let mut state = MockState::default();
        seed_previous_canonical_collapse_placeholder_if_absent(&mut state, recovered.height, 0x95);
        with_ctx(|ctx| {
            run_async(registry.handle_service_call(
                &mut state,
                "publish_aft_recovery_capsule@v1",
                &codec::to_bytes_canonical(&capsule).unwrap(),
                ctx,
            ))
            .unwrap();
            for certificate in &certificates {
                run_async(registry.handle_service_call(
                    &mut state,
                    "publish_aft_recovery_witness_certificate@v1",
                    &codec::to_bytes_canonical(certificate).unwrap(),
                    ctx,
                ))
                .unwrap();
            }
            for material in &materials {
                let receipt = material.to_recovery_share_receipt();
                run_async(registry.handle_service_call(
                    &mut state,
                    "publish_aft_recovery_share_receipt@v1",
                    &codec::to_bytes_canonical(&receipt).unwrap(),
                    ctx,
                ))
                .unwrap();
                run_async(registry.handle_service_call(
                    &mut state,
                    "publish_aft_recovery_share_material@v1",
                    &codec::to_bytes_canonical(material).unwrap(),
                    ctx,
                ))
                .unwrap();
            }
            run_async(registry.handle_service_call(
                &mut state,
                "publish_aft_recovered_publication_bundle@v1",
                &codec::to_bytes_canonical(&recovered).unwrap(),
                ctx,
            ))
            .unwrap();
        });

        let close = GuardianRegistry::load_canonical_bulletin_close(&state, recovered.height)
            .expect("load canonical bulletin close")
            .expect("canonical bulletin close should exist");
        let surface =
            GuardianRegistry::extract_published_bulletin_surface(&state, recovered.height)
                .expect("load bulletin surface")
                .expect("bulletin surface should exist");

        assert_eq!(close, expected_close);
        assert_eq!(surface, expected_surface);
        assert!(state
            .get(
                &aft_recovered_publication_bundle_key(
                    recovered.height,
                    &recovered.block_commitment_hash,
                    &recovered.supporting_witness_manifest_hashes,
                )
                .unwrap(),
            )
            .unwrap()
            .is_some());
    }

    #[test]
    fn publishing_recovered_publication_bundle_with_omission_proof_materializes_abort_without_membership_updates(
    ) {
        let registry = production_registry_without_accountable_membership_updates();
        let offender = AccountId([0x91u8; 32]);
        let omission_tx_hash = [0xa7u8; 32];
        let (capsule, certificates, materials, recovered) =
            sample_recovered_publication_bundle_fixture_3_of_5_with_omission(
                82,
                160,
                offender,
                omission_tx_hash,
            );
        let (_, expected_bundle) =
            recover_canonical_order_publication_bundle_from_share_materials(&materials)
                .expect("reconstruct recovered publication bundle");
        let expected_close = build_canonical_bulletin_close(
            &expected_bundle.bulletin_commitment,
            &expected_bundle.bulletin_availability_certificate,
        )
        .expect("canonical bulletin close");
        let omission = expected_bundle
            .canonical_order_certificate
            .omission_proofs
            .first()
            .cloned()
            .expect("recovered omission proof");
        let mut expected_surface = expected_bundle.bulletin_entries.clone();
        expected_surface.sort_unstable_by(|left, right| left.tx_hash.cmp(&right.tx_hash));

        let mut state = MockState::default();
        state
            .insert(
                VALIDATOR_SET_KEY,
                &write_validator_sets(&validator_sets(&[(18, 1), (145, 1), (19, 1)])).unwrap(),
            )
            .unwrap();
        seed_previous_canonical_collapse_placeholder_if_absent(&mut state, recovered.height, 0x96);

        with_ctx(|ctx| {
            run_async(registry.handle_service_call(
                &mut state,
                "publish_aft_recovery_capsule@v1",
                &codec::to_bytes_canonical(&capsule).unwrap(),
                ctx,
            ))
            .unwrap();
            for certificate in &certificates {
                run_async(registry.handle_service_call(
                    &mut state,
                    "publish_aft_recovery_witness_certificate@v1",
                    &codec::to_bytes_canonical(certificate).unwrap(),
                    ctx,
                ))
                .unwrap();
            }
            for material in &materials {
                let receipt = material.to_recovery_share_receipt();
                run_async(registry.handle_service_call(
                    &mut state,
                    "publish_aft_recovery_share_receipt@v1",
                    &codec::to_bytes_canonical(&receipt).unwrap(),
                    ctx,
                ))
                .unwrap();
                run_async(registry.handle_service_call(
                    &mut state,
                    "publish_aft_recovery_share_material@v1",
                    &codec::to_bytes_canonical(material).unwrap(),
                    ctx,
                ))
                .unwrap();
            }
            run_async(registry.handle_service_call(
                &mut state,
                "publish_aft_recovered_publication_bundle@v1",
                &codec::to_bytes_canonical(&recovered).unwrap(),
                ctx,
            ))
            .unwrap();
        });

        let stored_abort: CanonicalOrderAbort = codec::from_bytes_canonical(
            &state
                .get(&aft_canonical_order_abort_key(recovered.height))
                .unwrap()
                .expect("order abort stored"),
        )
        .unwrap();
        assert_eq!(
            stored_abort.reason,
            CanonicalOrderAbortReason::OmissionDominated
        );
        assert_eq!(
            stored_abort.canonical_order_certificate_hash,
            canonical_order_certificate_hash(&expected_bundle.canonical_order_certificate)
                .expect("canonical order certificate hash")
        );
        assert_eq!(
            stored_abort.bulletin_close_hash,
            canonical_bulletin_close_hash(&expected_close).expect("canonical bulletin close hash")
        );
        assert_eq!(
            GuardianRegistry::load_bulletin_commitment(&state, recovered.height).unwrap(),
            Some(expected_bundle.bulletin_commitment.clone())
        );
        assert_eq!(
            GuardianRegistry::load_bulletin_surface_entries(&state, recovered.height).unwrap(),
            expected_surface
        );
        assert_eq!(
            GuardianRegistry::extract_published_bulletin_surface(&state, recovered.height).unwrap(),
            None
        );
        assert_eq!(
            GuardianRegistry::load_bulletin_availability_certificate(&state, recovered.height)
                .unwrap(),
            None
        );
        assert_eq!(
            GuardianRegistry::load_canonical_bulletin_close(&state, recovered.height).unwrap(),
            None
        );
        assert!(state
            .get(&aft_order_certificate_key(recovered.height))
            .unwrap()
            .is_none());
        assert!(state
            .get(&aft_bulletin_availability_certificate_key(recovered.height))
            .unwrap()
            .is_none());
        assert!(state
            .get(&aft_canonical_bulletin_close_key(recovered.height))
            .unwrap()
            .is_none());

        let stored_omission: OmissionProof = codec::from_bytes_canonical(
            &state
                .get(&aft_omission_proof_key(omission.height, &omission.tx_hash))
                .unwrap()
                .expect("omission proof stored"),
        )
        .unwrap();
        assert_eq!(stored_omission, omission);
        assert_eq!(
            GuardianRegistry::load_recovered_publication_bundles(
                &state,
                recovered.height,
                &recovered.block_commitment_hash,
            )
            .unwrap(),
            vec![recovered.clone()]
        );
        assert!(state.get(QUARANTINED_VALIDATORS_KEY).unwrap().is_none());

        let stored_sets = read_validator_sets(
            &state
                .get(VALIDATOR_SET_KEY)
                .unwrap()
                .expect("validator sets stored"),
        )
        .unwrap();
        assert!(stored_sets.next.is_none());
        assert!(stored_sets
            .current
            .validators
            .iter()
            .any(|validator| validator.account_id == offender));

        let evidence_registry: BTreeSet<[u8; 32]> = codec::from_bytes_canonical(
            &state
                .get(EVIDENCE_REGISTRY_KEY)
                .unwrap()
                .expect("evidence registry stored"),
        )
        .unwrap();
        assert_eq!(evidence_registry.len(), 1);
    }

    #[test]
    fn publishing_recovered_publication_bundle_requires_sorted_supporting_witnesses() {
        let registry = production_registry();
        let (capsule, certificates, materials, mut recovered) =
            sample_recovered_publication_bundle_fixture(81, 100);
        recovered.supporting_witness_manifest_hashes.swap(0, 1);

        let mut state = MockState::default();
        with_ctx(|ctx| {
            run_async(registry.handle_service_call(
                &mut state,
                "publish_aft_recovery_capsule@v1",
                &codec::to_bytes_canonical(&capsule).unwrap(),
                ctx,
            ))
            .unwrap();
            for certificate in &certificates {
                run_async(registry.handle_service_call(
                    &mut state,
                    "publish_aft_recovery_witness_certificate@v1",
                    &codec::to_bytes_canonical(certificate).unwrap(),
                    ctx,
                ))
                .unwrap();
            }
            for material in &materials {
                let receipt = material.to_recovery_share_receipt();
                run_async(registry.handle_service_call(
                    &mut state,
                    "publish_aft_recovery_share_receipt@v1",
                    &codec::to_bytes_canonical(&receipt).unwrap(),
                    ctx,
                ))
                .unwrap();
                run_async(registry.handle_service_call(
                    &mut state,
                    "publish_aft_recovery_share_material@v1",
                    &codec::to_bytes_canonical(material).unwrap(),
                    ctx,
                ))
                .unwrap();
            }
            let err = run_async(registry.handle_service_call(
                &mut state,
                "publish_aft_recovered_publication_bundle@v1",
                &codec::to_bytes_canonical(&recovered).unwrap(),
                ctx,
            ))
            .unwrap_err();
            assert!(err
                .to_string()
                .contains("canonical sorted supporting witness manifests"));
        });
    }

    #[test]
    fn publishing_conflicting_recovered_publication_bundles_materializes_abort() {
        let (capsule, certificates, materials, recovered) =
            sample_recovered_publication_bundle_fixture(82, 110);
        let (_, _, conflicting_materials_template, conflicting_recovered_template) =
            sample_recovered_publication_bundle_fixture(82, 111);
        let conflicting_witnesses = [[201u8; 32], [202u8; 32]];
        let conflicting_share_commitments = [[203u8; 32], [204u8; 32]];
        let conflicting_certificates = conflicting_witnesses
            .iter()
            .zip(conflicting_share_commitments.iter())
            .map(|(witness_manifest_hash, share_commitment_hash)| {
                sample_recovery_witness_certificate(
                    &capsule,
                    *witness_manifest_hash,
                    *share_commitment_hash,
                )
            })
            .collect::<Vec<_>>();
        let conflicting_materials = conflicting_materials_template
            .iter()
            .zip(conflicting_witnesses.iter())
            .zip(conflicting_share_commitments.iter())
            .map(
                |((material, witness_manifest_hash), share_commitment_hash)| {
                    RecoveryShareMaterial {
                        witness_manifest_hash: *witness_manifest_hash,
                        share_commitment_hash: *share_commitment_hash,
                        ..material.clone()
                    }
                },
            )
            .collect::<Vec<_>>();
        let conflicting_recovered = RecoveredPublicationBundle {
            supporting_witness_manifest_hashes: conflicting_witnesses.to_vec(),
            ..conflicting_recovered_template
        };

        assert_conflicting_recovered_publication_bundles_materialize_abort(
            capsule,
            certificates,
            materials,
            recovered,
            conflicting_certificates,
            conflicting_materials,
            conflicting_recovered,
        );
    }

    #[test]
    fn publishing_conflicting_recovered_publication_bundles_materializes_abort_for_three_of_seven_non_overlap(
    ) {
        let coding = gf256_recovery_coding(7, 3);
        let (capsule, certificates, materials, recovered) =
            sample_recovered_publication_bundle_fixture_with_scheme(83, 120, coding, &[0, 1, 2]);
        let (_, _, conflicting_materials_template, conflicting_recovered_template) =
            sample_recovered_publication_bundle_fixture_with_scheme(83, 121, coding, &[3, 4, 5]);
        let conflicting_witnesses = [[211u8; 32], [212u8; 32], [213u8; 32]];
        let conflicting_share_commitments = [[214u8; 32], [215u8; 32], [216u8; 32]];
        let conflicting_certificates = conflicting_witnesses
            .iter()
            .zip(conflicting_share_commitments.iter())
            .map(|(witness_manifest_hash, share_commitment_hash)| {
                sample_recovery_witness_certificate(
                    &capsule,
                    *witness_manifest_hash,
                    *share_commitment_hash,
                )
            })
            .collect::<Vec<_>>();
        let conflicting_materials = conflicting_materials_template
            .iter()
            .zip(conflicting_witnesses.iter())
            .zip(conflicting_share_commitments.iter())
            .map(
                |((material, witness_manifest_hash), share_commitment_hash)| {
                    RecoveryShareMaterial {
                        witness_manifest_hash: *witness_manifest_hash,
                        share_commitment_hash: *share_commitment_hash,
                        ..material.clone()
                    }
                },
            )
            .collect::<Vec<_>>();
        let conflicting_recovered = RecoveredPublicationBundle {
            supporting_witness_manifest_hashes: conflicting_witnesses.to_vec(),
            ..conflicting_recovered_template
        };

        assert_conflicting_recovered_publication_bundles_materialize_abort(
            capsule,
            certificates,
            materials,
            recovered,
            conflicting_certificates,
            conflicting_materials,
            conflicting_recovered,
        );
    }

    #[test]
    fn publishing_conflicting_recovery_capsule_is_rejected() {
        let registry = production_registry();
        let capsule = sample_recovery_capsule(79);
        let conflicting = RecoveryCapsule {
            payload_commitment_hash: [0x61u8; 32],
            ..capsule.clone()
        };

        let mut state = MockState::default();
        with_ctx(|ctx| {
            run_async(registry.handle_service_call(
                &mut state,
                "publish_aft_recovery_capsule@v1",
                &codec::to_bytes_canonical(&capsule).unwrap(),
                ctx,
            ))
            .expect("first capsule publish succeeds");

            let err = run_async(registry.handle_service_call(
                &mut state,
                "publish_aft_recovery_capsule@v1",
                &codec::to_bytes_canonical(&conflicting).unwrap(),
                ctx,
            ))
            .expect_err("conflicting capsule must be rejected");
            assert!(err
                .to_string()
                .contains("conflicting aft recovery capsule already published"));
        });
    }

    #[test]
    fn publishing_recovery_share_receipt_requires_matching_witness_certificate() {
        let registry = production_registry();
        let capsule = sample_recovery_capsule(72);
        let witness_manifest_hash = [21u8; 32];
        let certificate =
            sample_recovery_witness_certificate(&capsule, witness_manifest_hash, [22u8; 32]);
        let bad_receipt = RecoveryShareReceipt {
            height: capsule.height,
            witness_manifest_hash,
            block_commitment_hash: [23u8; 32],
            share_commitment_hash: [24u8; 32],
        };

        let mut state = MockState::default();
        with_ctx(|ctx| {
            run_async(registry.handle_service_call(
                &mut state,
                "publish_aft_recovery_capsule@v1",
                &codec::to_bytes_canonical(&capsule).unwrap(),
                ctx,
            ))
            .unwrap();
            run_async(registry.handle_service_call(
                &mut state,
                "publish_aft_recovery_witness_certificate@v1",
                &codec::to_bytes_canonical(&certificate).unwrap(),
                ctx,
            ))
            .unwrap();
            let err = run_async(registry.handle_service_call(
                &mut state,
                "publish_aft_recovery_share_receipt@v1",
                &codec::to_bytes_canonical(&bad_receipt).unwrap(),
                ctx,
            ))
            .unwrap_err();
            assert!(err
                .to_string()
                .contains("must match the witness certificate share commitment"));
        });

        assert!(state
            .get(&aft_recovery_share_receipt_key(
                capsule.height,
                &witness_manifest_hash,
                &bad_receipt.block_commitment_hash,
            ))
            .unwrap()
            .is_none());
    }

    #[test]
    fn publishing_recovery_share_material_requires_matching_receipt() {
        let registry = production_registry();
        let capsule = sample_recovery_capsule(72);
        let witness_manifest_hash = [21u8; 32];
        let certificate =
            sample_recovery_witness_certificate(&capsule, witness_manifest_hash, [22u8; 32]);
        let material = RecoveryShareMaterial {
            height: capsule.height,
            witness_manifest_hash,
            block_commitment_hash: [23u8; 32],
            coding: xor_recovery_coding(3, 2),
            share_index: 1,
            share_commitment_hash: certificate.share_commitment_hash,
            material_bytes: vec![0xdd, 0xee, 0xff],
        };

        let mut state = MockState::default();
        with_ctx(|ctx| {
            run_async(registry.handle_service_call(
                &mut state,
                "publish_aft_recovery_capsule@v1",
                &codec::to_bytes_canonical(&capsule).unwrap(),
                ctx,
            ))
            .unwrap();
            run_async(registry.handle_service_call(
                &mut state,
                "publish_aft_recovery_witness_certificate@v1",
                &codec::to_bytes_canonical(&certificate).unwrap(),
                ctx,
            ))
            .unwrap();
            let err = run_async(registry.handle_service_call(
                &mut state,
                "publish_aft_recovery_share_material@v1",
                &codec::to_bytes_canonical(&material).unwrap(),
                ctx,
            ))
            .unwrap_err();
            assert!(err
                .to_string()
                .contains("requires a published matching recovery share receipt"));
        });

        assert!(state
            .get(&aft_recovery_share_material_key(
                capsule.height,
                &witness_manifest_hash,
                &material.block_commitment_hash,
            ))
            .unwrap()
            .is_none());
    }

    #[test]
    fn publishing_missing_recovery_share_round_trips_without_receipts() {
        let registry = production_registry();
        let capsule = sample_recovery_capsule(73);
        let witness_manifest_hash = [25u8; 32];
        let certificate =
            sample_recovery_witness_certificate(&capsule, witness_manifest_hash, [26u8; 32]);
        let missing = MissingRecoveryShare {
            height: capsule.height,
            witness_manifest_hash,
            recovery_capsule_hash: certificate.recovery_capsule_hash,
            recovery_window_close_ms: capsule.recovery_window_close_ms,
        };

        let mut state = MockState::default();
        with_ctx(|ctx| {
            for (method, params) in [
                (
                    "publish_aft_recovery_capsule@v1",
                    codec::to_bytes_canonical(&capsule).unwrap(),
                ),
                (
                    "publish_aft_recovery_witness_certificate@v1",
                    codec::to_bytes_canonical(&certificate).unwrap(),
                ),
                (
                    "publish_aft_missing_recovery_share@v1",
                    codec::to_bytes_canonical(&missing).unwrap(),
                ),
            ] {
                run_async(registry.handle_service_call(&mut state, method, &params, ctx)).unwrap();
            }
        });

        assert_eq!(
            GuardianRegistry::load_missing_recovery_share(
                &state,
                capsule.height,
                &witness_manifest_hash
            )
            .unwrap(),
            Some(missing.clone())
        );
        assert!(state
            .get(&aft_missing_recovery_share_key(
                capsule.height,
                &witness_manifest_hash,
            ))
            .unwrap()
            .is_some());
    }

    #[test]
    fn publishing_missing_recovery_share_after_receipt_is_rejected() {
        let registry = production_registry();
        let capsule = sample_recovery_capsule(74);
        let witness_manifest_hash = [27u8; 32];
        let certificate =
            sample_recovery_witness_certificate(&capsule, witness_manifest_hash, [28u8; 32]);
        let receipt = RecoveryShareReceipt {
            height: capsule.height,
            witness_manifest_hash,
            block_commitment_hash: [29u8; 32],
            share_commitment_hash: certificate.share_commitment_hash,
        };
        let missing = MissingRecoveryShare {
            height: capsule.height,
            witness_manifest_hash,
            recovery_capsule_hash: certificate.recovery_capsule_hash,
            recovery_window_close_ms: capsule.recovery_window_close_ms,
        };

        let mut state = MockState::default();
        with_ctx(|ctx| {
            for (method, params) in [
                (
                    "publish_aft_recovery_capsule@v1",
                    codec::to_bytes_canonical(&capsule).unwrap(),
                ),
                (
                    "publish_aft_recovery_witness_certificate@v1",
                    codec::to_bytes_canonical(&certificate).unwrap(),
                ),
                (
                    "publish_aft_recovery_share_receipt@v1",
                    codec::to_bytes_canonical(&receipt).unwrap(),
                ),
            ] {
                run_async(registry.handle_service_call(&mut state, method, &params, ctx)).unwrap();
            }
            let err = run_async(registry.handle_service_call(
                &mut state,
                "publish_aft_missing_recovery_share@v1",
                &codec::to_bytes_canonical(&missing).unwrap(),
                ctx,
            ))
            .unwrap_err();
            assert!(err
                .to_string()
                .contains("after a recovery receipt already exists"));
        });

        assert!(state
            .get(&aft_missing_recovery_share_key(
                capsule.height,
                &witness_manifest_hash,
            ))
            .unwrap()
            .is_none());
    }

    #[test]
    fn recovery_threshold_status_reports_recoverable_for_matching_receipts() {
        let registry = production_registry();
        let capsule = sample_recovery_capsule(75);
        let witness_a = [31u8; 32];
        let witness_b = [32u8; 32];
        let witness_c = [33u8; 32];
        let block_commitment_hash = [34u8; 32];
        let certificate_a = sample_recovery_witness_certificate(&capsule, witness_a, [35u8; 32]);
        let certificate_b = sample_recovery_witness_certificate(&capsule, witness_b, [36u8; 32]);
        let certificate_c = sample_recovery_witness_certificate(&capsule, witness_c, [37u8; 32]);
        let receipt_a = RecoveryShareReceipt {
            height: capsule.height,
            witness_manifest_hash: witness_a,
            block_commitment_hash,
            share_commitment_hash: certificate_a.share_commitment_hash,
        };
        let receipt_b = RecoveryShareReceipt {
            height: capsule.height,
            witness_manifest_hash: witness_b,
            block_commitment_hash,
            share_commitment_hash: certificate_b.share_commitment_hash,
        };

        let mut state = MockState::default();
        with_ctx(|ctx| {
            for (method, params) in [
                (
                    "publish_aft_recovery_capsule@v1",
                    codec::to_bytes_canonical(&capsule).unwrap(),
                ),
                (
                    "publish_aft_recovery_witness_certificate@v1",
                    codec::to_bytes_canonical(&certificate_a).unwrap(),
                ),
                (
                    "publish_aft_recovery_witness_certificate@v1",
                    codec::to_bytes_canonical(&certificate_b).unwrap(),
                ),
                (
                    "publish_aft_recovery_witness_certificate@v1",
                    codec::to_bytes_canonical(&certificate_c).unwrap(),
                ),
                (
                    "publish_aft_recovery_share_receipt@v1",
                    codec::to_bytes_canonical(&receipt_a).unwrap(),
                ),
                (
                    "publish_aft_recovery_share_receipt@v1",
                    codec::to_bytes_canonical(&receipt_b).unwrap(),
                ),
            ] {
                run_async(registry.handle_service_call(&mut state, method, &params, ctx)).unwrap();
            }
        });

        assert_eq!(
            GuardianRegistry::load_recovery_threshold_status(
                &state,
                capsule.height,
                &[witness_a, witness_b, witness_c],
                2,
            )
            .unwrap(),
            RecoveryThresholdStatus::Recoverable(block_commitment_hash)
        );
    }

    #[test]
    fn recovery_threshold_status_reports_pending_when_threshold_is_still_reachable() {
        let registry = production_registry();
        let capsule = sample_recovery_capsule(76);
        let witness_a = [41u8; 32];
        let witness_b = [42u8; 32];
        let witness_c = [43u8; 32];
        let certificate_a = sample_recovery_witness_certificate(&capsule, witness_a, [44u8; 32]);
        let certificate_b = sample_recovery_witness_certificate(&capsule, witness_b, [45u8; 32]);
        let certificate_c = sample_recovery_witness_certificate(&capsule, witness_c, [46u8; 32]);
        let receipt_a = RecoveryShareReceipt {
            height: capsule.height,
            witness_manifest_hash: witness_a,
            block_commitment_hash: [47u8; 32],
            share_commitment_hash: certificate_a.share_commitment_hash,
        };

        let mut state = MockState::default();
        with_ctx(|ctx| {
            for (method, params) in [
                (
                    "publish_aft_recovery_capsule@v1",
                    codec::to_bytes_canonical(&capsule).unwrap(),
                ),
                (
                    "publish_aft_recovery_witness_certificate@v1",
                    codec::to_bytes_canonical(&certificate_a).unwrap(),
                ),
                (
                    "publish_aft_recovery_witness_certificate@v1",
                    codec::to_bytes_canonical(&certificate_b).unwrap(),
                ),
                (
                    "publish_aft_recovery_witness_certificate@v1",
                    codec::to_bytes_canonical(&certificate_c).unwrap(),
                ),
                (
                    "publish_aft_recovery_share_receipt@v1",
                    codec::to_bytes_canonical(&receipt_a).unwrap(),
                ),
            ] {
                run_async(registry.handle_service_call(&mut state, method, &params, ctx)).unwrap();
            }
        });

        assert_eq!(
            GuardianRegistry::load_recovery_threshold_status(
                &state,
                capsule.height,
                &[witness_a, witness_b, witness_c],
                2,
            )
            .unwrap(),
            RecoveryThresholdStatus::Pending
        );
    }

    #[test]
    fn recovery_threshold_status_reports_impossible_when_missingness_exhausts_capacity() {
        let registry = production_registry();
        let capsule = sample_recovery_capsule(77);
        let witness_a = [51u8; 32];
        let witness_b = [52u8; 32];
        let witness_c = [53u8; 32];
        let certificate_a = sample_recovery_witness_certificate(&capsule, witness_a, [54u8; 32]);
        let certificate_b = sample_recovery_witness_certificate(&capsule, witness_b, [55u8; 32]);
        let certificate_c = sample_recovery_witness_certificate(&capsule, witness_c, [56u8; 32]);
        let missing_a = MissingRecoveryShare {
            height: capsule.height,
            witness_manifest_hash: witness_a,
            recovery_capsule_hash: certificate_a.recovery_capsule_hash,
            recovery_window_close_ms: capsule.recovery_window_close_ms,
        };
        let missing_b = MissingRecoveryShare {
            height: capsule.height,
            witness_manifest_hash: witness_b,
            recovery_capsule_hash: certificate_b.recovery_capsule_hash,
            recovery_window_close_ms: capsule.recovery_window_close_ms,
        };

        let mut state = MockState::default();
        with_ctx(|ctx| {
            for (method, params) in [
                (
                    "publish_aft_recovery_capsule@v1",
                    codec::to_bytes_canonical(&capsule).unwrap(),
                ),
                (
                    "publish_aft_recovery_witness_certificate@v1",
                    codec::to_bytes_canonical(&certificate_a).unwrap(),
                ),
                (
                    "publish_aft_recovery_witness_certificate@v1",
                    codec::to_bytes_canonical(&certificate_b).unwrap(),
                ),
                (
                    "publish_aft_recovery_witness_certificate@v1",
                    codec::to_bytes_canonical(&certificate_c).unwrap(),
                ),
                (
                    "publish_aft_missing_recovery_share@v1",
                    codec::to_bytes_canonical(&missing_a).unwrap(),
                ),
                (
                    "publish_aft_missing_recovery_share@v1",
                    codec::to_bytes_canonical(&missing_b).unwrap(),
                ),
            ] {
                run_async(registry.handle_service_call(&mut state, method, &params, ctx)).unwrap();
            }
        });

        assert_eq!(
            GuardianRegistry::load_recovery_threshold_status(
                &state,
                capsule.height,
                &[witness_a, witness_b, witness_c],
                2,
            )
            .unwrap(),
            RecoveryThresholdStatus::Impossible
        );
    }

    #[test]
    fn publishing_missing_recovery_share_materializes_recovery_impossible_abort() {
        let registry = production_registry();
        let capsule = sample_recovery_capsule(77_001);
        let witness_a = [57u8; 32];
        let witness_b = [58u8; 32];
        let witness_c = [59u8; 32];
        let certificate_a = sample_recovery_witness_certificate(&capsule, witness_a, [60u8; 32]);
        let certificate_b = sample_recovery_witness_certificate(&capsule, witness_b, [61u8; 32]);
        let certificate_c = sample_recovery_witness_certificate(&capsule, witness_c, [62u8; 32]);
        let missing_a = MissingRecoveryShare {
            height: capsule.height,
            witness_manifest_hash: witness_a,
            recovery_capsule_hash: certificate_a.recovery_capsule_hash,
            recovery_window_close_ms: capsule.recovery_window_close_ms,
        };
        let missing_b = MissingRecoveryShare {
            height: capsule.height,
            witness_manifest_hash: witness_b,
            recovery_capsule_hash: certificate_b.recovery_capsule_hash,
            recovery_window_close_ms: capsule.recovery_window_close_ms,
        };

        let mut state = MockState::default();
        with_ctx(|ctx| {
            for (method, params) in [
                (
                    "publish_aft_recovery_capsule@v1",
                    codec::to_bytes_canonical(&capsule).unwrap(),
                ),
                (
                    "publish_aft_recovery_witness_certificate@v1",
                    codec::to_bytes_canonical(&certificate_a).unwrap(),
                ),
                (
                    "publish_aft_recovery_witness_certificate@v1",
                    codec::to_bytes_canonical(&certificate_b).unwrap(),
                ),
                (
                    "publish_aft_recovery_witness_certificate@v1",
                    codec::to_bytes_canonical(&certificate_c).unwrap(),
                ),
                (
                    "publish_aft_missing_recovery_share@v1",
                    codec::to_bytes_canonical(&missing_a).unwrap(),
                ),
                (
                    "publish_aft_missing_recovery_share@v1",
                    codec::to_bytes_canonical(&missing_b).unwrap(),
                ),
            ] {
                run_async(registry.handle_service_call(&mut state, method, &params, ctx)).unwrap();
            }
        });

        let abort = GuardianRegistry::load_canonical_order_abort(&state, capsule.height)
            .unwrap()
            .expect("recovery impossible state should materialize a canonical-order abort");
        assert_eq!(
            abort.reason,
            CanonicalOrderAbortReason::RecoveryThresholdImpossible
        );
        assert!(
            GuardianRegistry::load_canonical_bulletin_close(&state, capsule.height)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn recovery_threshold_status_excludes_conflicting_same_witness_receipts_from_support() {
        let registry = production_registry();
        let capsule = sample_recovery_capsule(78);
        let witness_a = [61u8; 32];
        let witness_b = [62u8; 32];
        let witness_c = [63u8; 32];
        let certificate_a = sample_recovery_witness_certificate(&capsule, witness_a, [64u8; 32]);
        let certificate_b = sample_recovery_witness_certificate(&capsule, witness_b, [65u8; 32]);
        let certificate_c = sample_recovery_witness_certificate(&capsule, witness_c, [66u8; 32]);
        let block_commitment_hash = [67u8; 32];
        let receipt_a_one = RecoveryShareReceipt {
            height: capsule.height,
            witness_manifest_hash: witness_a,
            block_commitment_hash,
            share_commitment_hash: certificate_a.share_commitment_hash,
        };
        let receipt_a_two = RecoveryShareReceipt {
            height: capsule.height,
            witness_manifest_hash: witness_a,
            block_commitment_hash: [68u8; 32],
            share_commitment_hash: certificate_a.share_commitment_hash,
        };
        let receipt_b = RecoveryShareReceipt {
            height: capsule.height,
            witness_manifest_hash: witness_b,
            block_commitment_hash,
            share_commitment_hash: certificate_b.share_commitment_hash,
        };
        let missing_c = MissingRecoveryShare {
            height: capsule.height,
            witness_manifest_hash: witness_c,
            recovery_capsule_hash: certificate_c.recovery_capsule_hash,
            recovery_window_close_ms: capsule.recovery_window_close_ms,
        };

        let mut state = MockState::default();
        with_ctx(|ctx| {
            for (method, params) in [
                (
                    "publish_aft_recovery_capsule@v1",
                    codec::to_bytes_canonical(&capsule).unwrap(),
                ),
                (
                    "publish_aft_recovery_witness_certificate@v1",
                    codec::to_bytes_canonical(&certificate_a).unwrap(),
                ),
                (
                    "publish_aft_recovery_witness_certificate@v1",
                    codec::to_bytes_canonical(&certificate_b).unwrap(),
                ),
                (
                    "publish_aft_recovery_witness_certificate@v1",
                    codec::to_bytes_canonical(&certificate_c).unwrap(),
                ),
                (
                    "publish_aft_recovery_share_receipt@v1",
                    codec::to_bytes_canonical(&receipt_a_one).unwrap(),
                ),
                (
                    "publish_aft_recovery_share_receipt@v1",
                    codec::to_bytes_canonical(&receipt_a_two).unwrap(),
                ),
                (
                    "publish_aft_recovery_share_receipt@v1",
                    codec::to_bytes_canonical(&receipt_b).unwrap(),
                ),
                (
                    "publish_aft_missing_recovery_share@v1",
                    codec::to_bytes_canonical(&missing_c).unwrap(),
                ),
            ] {
                run_async(registry.handle_service_call(&mut state, method, &params, ctx)).unwrap();
            }
        });

        assert_eq!(
            GuardianRegistry::load_recovery_threshold_status(
                &state,
                capsule.height,
                &[witness_a, witness_b, witness_c],
                2,
            )
            .unwrap(),
            RecoveryThresholdStatus::Impossible
        );
    }

    #[test]
    fn reporting_aft_omission_auto_accounts_offender_and_stages_next_epoch_eviction() {
        let registry = production_registry();
        let offender = AccountId([11u8; 32]);
        let omission = OmissionProof {
            height: 9,
            offender_account_id: offender,
            tx_hash: [51u8; 32],
            bulletin_root: [52u8; 32],
            details: "candidate order omitted an admitted transaction".into(),
        };

        let mut state = MockState::default();
        state
            .insert(
                VALIDATOR_SET_KEY,
                &write_validator_sets(&validator_sets(&[(7, 1), (11, 1), (12, 1)])).unwrap(),
            )
            .unwrap();

        with_ctx(|ctx| {
            run_async(registry.handle_service_call(
                &mut state,
                "report_aft_omission@v1",
                &codec::to_bytes_canonical(&omission).unwrap(),
                ctx,
            ))
            .unwrap();
        });

        let quarantined: BTreeSet<AccountId> = codec::from_bytes_canonical(
            &state
                .get(QUARANTINED_VALIDATORS_KEY)
                .unwrap()
                .expect("quarantine set stored"),
        )
        .unwrap();
        assert!(quarantined.contains(&offender));

        let stored_sets = read_validator_sets(
            &state
                .get(VALIDATOR_SET_KEY)
                .unwrap()
                .expect("validator sets stored"),
        )
        .unwrap();
        let next = stored_sets.next.expect("next validator set staged");
        assert_eq!(next.effective_from_height, 43);
        assert!(!next
            .validators
            .iter()
            .any(|validator| validator.account_id == offender));

        let evidence_registry: BTreeSet<[u8; 32]> = codec::from_bytes_canonical(
            &state
                .get(EVIDENCE_REGISTRY_KEY)
                .unwrap()
                .expect("evidence registry stored"),
        )
        .unwrap();
        assert_eq!(evidence_registry.len(), 1);
    }

    #[test]
    fn publishing_aft_canonical_order_artifact_bundle_with_omission_proof_materializes_abort_without_membership_updates(
    ) {
        let registry = production_registry_without_accountable_membership_updates();
        let base_header = ioi_types::app::BlockHeader {
            height: 10,
            view: 2,
            parent_hash: [11u8; 32],
            parent_state_root: StateRoot(vec![1u8; 32]),
            state_root: StateRoot(vec![2u8; 32]),
            transactions_root: Vec::new(),
            timestamp: 1_760_000_211,
            timestamp_ms: 1_760_000_211_000,
            gas_used: 0,
            validator_set: Vec::new(),
            producer_account_id: AccountId([12u8; 32]),
            producer_key_suite: SignatureSuite::ED25519,
            producer_pubkey_hash: [13u8; 32],
            producer_pubkey: Vec::new(),
            signature: Vec::new(),
            oracle_counter: 0,
            oracle_trace_hash: [0u8; 32],
            parent_qc: QuorumCertificate::default(),
            previous_canonical_collapse_commitment_hash: [0u8; 32],
            canonical_collapse_extension_certificate: None,
            publication_frontier: None,
            guardian_certificate: None,
            sealed_finality_proof: None,
            canonical_order_certificate: None,
            timeout_certificate: None,
        };
        let tx_one = ChainTransaction::System(Box::new(SystemTransaction {
            header: SignHeader {
                account_id: AccountId([31u8; 32]),
                nonce: 1,
                chain_id: ChainId(1),
                tx_version: 1,
                session_auth: None,
            },
            payload: SystemPayload::CallService {
                service_id: "guardian_registry".into(),
                method: "publish_aft_bulletin_commitment@v1".into(),
                params: vec![1],
            },
            signature_proof: SignatureProof::default(),
        }));
        let tx_two = ChainTransaction::System(Box::new(SystemTransaction {
            header: SignHeader {
                account_id: AccountId([32u8; 32]),
                nonce: 1,
                chain_id: ChainId(1),
                tx_version: 1,
                session_auth: None,
            },
            payload: SystemPayload::CallService {
                service_id: "guardian_registry".into(),
                method: "publish_aft_canonical_order_artifact_bundle@v1".into(),
                params: vec![2],
            },
            signature_proof: SignatureProof::default(),
        }));

        let ordered_transactions =
            canonicalize_transactions_for_header(&base_header, &[tx_one, tx_two]).unwrap();
        let tx_hashes: Vec<[u8; 32]> = ordered_transactions
            .iter()
            .map(|tx| tx.hash().unwrap())
            .collect();
        let mut header = base_header;
        header.transactions_root = canonical_transaction_root_from_hashes(&tx_hashes).unwrap();
        let mut certificate =
            build_committed_surface_canonical_order_certificate(&header, &ordered_transactions)
                .unwrap();
        let offender = AccountId([44u8; 32]);
        let omission = OmissionProof {
            height: header.height,
            offender_account_id: offender,
            tx_hash: [45u8; 32],
            bulletin_root: certificate.bulletin_commitment.bulletin_root,
            details: "bundle-carried omission remains decisive without membership penalties".into(),
        };
        certificate.omission_proofs = vec![omission.clone()];
        let bundle = CanonicalOrderPublicationBundle {
            bulletin_commitment: certificate.bulletin_commitment.clone(),
            bulletin_entries: build_bulletin_surface_entries(header.height, &ordered_transactions)
                .unwrap(),
            bulletin_availability_certificate: certificate
                .bulletin_availability_certificate
                .clone(),
            canonical_order_certificate: certificate.clone(),
        };

        let mut state = MockState::default();
        state
            .insert(
                VALIDATOR_SET_KEY,
                &write_validator_sets(&validator_sets(&[(12, 1), (44, 1), (46, 1)])).unwrap(),
            )
            .unwrap();

        with_ctx(|ctx| {
            run_async(registry.handle_service_call(
                &mut state,
                "publish_aft_canonical_order_artifact_bundle@v1",
                &codec::to_bytes_canonical(&bundle).unwrap(),
                ctx,
            ))
            .unwrap();
        });

        let stored_abort: CanonicalOrderAbort = codec::from_bytes_canonical(
            &state
                .get(&aft_canonical_order_abort_key(header.height))
                .unwrap()
                .expect("order abort stored"),
        )
        .unwrap();
        assert_eq!(
            stored_abort.reason,
            CanonicalOrderAbortReason::OmissionDominated
        );
        assert_eq!(
            stored_abort.canonical_order_certificate_hash,
            canonical_order_certificate_hash(&certificate).unwrap()
        );
        assert!(state
            .get(&aft_order_certificate_key(header.height))
            .unwrap()
            .is_none());
        assert!(state
            .get(&aft_bulletin_availability_certificate_key(header.height))
            .unwrap()
            .is_none());
        assert!(state
            .get(&aft_canonical_bulletin_close_key(header.height))
            .unwrap()
            .is_none());
        assert!(state.get(QUARANTINED_VALIDATORS_KEY).unwrap().is_none());

        let stored_sets = read_validator_sets(
            &state
                .get(VALIDATOR_SET_KEY)
                .unwrap()
                .expect("validator sets stored"),
        )
        .unwrap();
        assert!(stored_sets.next.is_none());
        assert!(stored_sets
            .current
            .validators
            .iter()
            .any(|validator| validator.account_id == offender));

        let evidence_registry: BTreeSet<[u8; 32]> = codec::from_bytes_canonical(
            &state
                .get(EVIDENCE_REGISTRY_KEY)
                .unwrap()
                .expect("evidence registry stored"),
        )
        .unwrap();
        assert_eq!(evidence_registry.len(), 1);
    }

    #[test]
    fn reporting_aft_omission_remains_published_when_accountable_membership_updates_are_disabled() {
        let registry = production_registry_without_accountable_membership_updates();
        let offender = AccountId([14u8; 32]);
        let omission = OmissionProof {
            height: 10,
            offender_account_id: offender,
            tx_hash: [53u8; 32],
            bulletin_root: [54u8; 32],
            details: "negative ordering object remains decisive without membership penalties"
                .into(),
        };

        let mut state = MockState::default();
        state
            .insert(
                VALIDATOR_SET_KEY,
                &write_validator_sets(&validator_sets(&[(7, 1), (14, 1), (15, 1)])).unwrap(),
            )
            .unwrap();

        with_ctx(|ctx| {
            run_async(registry.handle_service_call(
                &mut state,
                "report_aft_omission@v1",
                &codec::to_bytes_canonical(&omission).unwrap(),
                ctx,
            ))
            .unwrap();
        });

        let stored_omission: OmissionProof = codec::from_bytes_canonical(
            &state
                .get(&aft_omission_proof_key(omission.height, &omission.tx_hash))
                .unwrap()
                .expect("omission proof stored"),
        )
        .unwrap();
        assert_eq!(stored_omission, omission);
        assert!(state.get(QUARANTINED_VALIDATORS_KEY).unwrap().is_none());

        let stored_sets = read_validator_sets(
            &state
                .get(VALIDATOR_SET_KEY)
                .unwrap()
                .expect("validator sets stored"),
        )
        .unwrap();
        assert!(stored_sets.next.is_none());
        assert!(stored_sets
            .current
            .validators
            .iter()
            .any(|validator| validator.account_id == offender));

        let evidence_registry: BTreeSet<[u8; 32]> = codec::from_bytes_canonical(
            &state
                .get(EVIDENCE_REGISTRY_KEY)
                .unwrap()
                .expect("evidence registry stored"),
        )
        .unwrap();
        assert_eq!(evidence_registry.len(), 1);
    }

    #[test]
    fn reporting_aft_omission_after_positive_ordering_artifacts_materializes_abort_dominance() {
        let registry = production_registry();
        let base_header = ioi_types::app::BlockHeader {
            height: 18,
            view: 2,
            parent_hash: [31u8; 32],
            parent_state_root: StateRoot(vec![1u8; 32]),
            state_root: StateRoot(vec![2u8; 32]),
            transactions_root: Vec::new(),
            timestamp: 1_760_000_411,
            timestamp_ms: 1_760_000_411_000,
            gas_used: 0,
            validator_set: Vec::new(),
            producer_account_id: AccountId([32u8; 32]),
            producer_key_suite: SignatureSuite::ED25519,
            producer_pubkey_hash: [33u8; 32],
            producer_pubkey: Vec::new(),
            signature: Vec::new(),
            oracle_counter: 0,
            oracle_trace_hash: [0u8; 32],
            parent_qc: QuorumCertificate::default(),
            previous_canonical_collapse_commitment_hash: [0u8; 32],
            canonical_collapse_extension_certificate: None,
            publication_frontier: None,
            guardian_certificate: None,
            sealed_finality_proof: None,
            canonical_order_certificate: None,
            timeout_certificate: None,
        };
        let tx = ChainTransaction::System(Box::new(SystemTransaction {
            header: SignHeader {
                account_id: AccountId([34u8; 32]),
                nonce: 1,
                chain_id: ChainId(1),
                tx_version: 1,
                session_auth: None,
            },
            payload: SystemPayload::CallService {
                service_id: "guardian_registry".into(),
                method: "publish_aft_bulletin_commitment@v1".into(),
                params: vec![1],
            },
            signature_proof: SignatureProof::default(),
        }));
        let ordered_transactions =
            canonicalize_transactions_for_header(&base_header, &[tx]).unwrap();
        let tx_hashes: Vec<[u8; 32]> = ordered_transactions
            .iter()
            .map(|tx| tx.hash().unwrap())
            .collect();
        let mut header = base_header;
        header.transactions_root = canonical_transaction_root_from_hashes(&tx_hashes).unwrap();
        let certificate =
            build_committed_surface_canonical_order_certificate(&header, &ordered_transactions)
                .unwrap();
        let bundle = CanonicalOrderPublicationBundle {
            bulletin_commitment: certificate.bulletin_commitment.clone(),
            bulletin_entries: build_bulletin_surface_entries(header.height, &ordered_transactions)
                .unwrap(),
            bulletin_availability_certificate: certificate
                .bulletin_availability_certificate
                .clone(),
            canonical_order_certificate: certificate.clone(),
        };
        let omission = OmissionProof {
            height: header.height,
            offender_account_id: AccountId([35u8; 32]),
            tx_hash: [36u8; 32],
            bulletin_root: certificate.bulletin_commitment.bulletin_root,
            details: "late omission dominates positive ordering artifacts".into(),
        };

        let mut state = MockState::default();
        state
            .insert(
                VALIDATOR_SET_KEY,
                &write_validator_sets(&validator_sets(&[(32, 1), (35, 1), (36, 1)])).unwrap(),
            )
            .unwrap();

        with_ctx(|ctx| {
            run_async(registry.handle_service_call(
                &mut state,
                "publish_aft_canonical_order_artifact_bundle@v1",
                &codec::to_bytes_canonical(&bundle).unwrap(),
                ctx,
            ))
            .unwrap();
            run_async(registry.handle_service_call(
                &mut state,
                "report_aft_omission@v1",
                &codec::to_bytes_canonical(&omission).unwrap(),
                ctx,
            ))
            .unwrap();
        });

        let stored_abort: CanonicalOrderAbort = codec::from_bytes_canonical(
            &state
                .get(&aft_canonical_order_abort_key(header.height))
                .unwrap()
                .expect("order abort stored"),
        )
        .unwrap();
        assert_eq!(
            stored_abort.reason,
            CanonicalOrderAbortReason::OmissionDominated
        );
        assert!(state
            .get(&aft_order_certificate_key(header.height))
            .unwrap()
            .is_none());
        assert!(state
            .get(&aft_bulletin_availability_certificate_key(header.height))
            .unwrap()
            .is_none());
        assert!(state
            .get(&aft_canonical_bulletin_close_key(header.height))
            .unwrap()
            .is_none());
    }

    #[test]
    fn transcript_mismatch_challenge_penalizes_producer_not_observer() {
        let registry = production_registry();
        let producer = AccountId([21u8; 32]);
        let observer = AccountId([22u8; 32]);
        let assignment = AsymptoteObserverAssignment {
            epoch: 7,
            producer_account_id: producer,
            height: 12,
            view: 3,
            round: 0,
            observer_account_id: observer,
        };
        let request = AsymptoteObserverObservationRequest {
            epoch: 7,
            assignment: assignment.clone(),
            block_hash: [61u8; 32],
            guardian_manifest_hash: [62u8; 32],
            guardian_decision_hash: [63u8; 32],
            guardian_counter: 64,
            guardian_trace_hash: [65u8; 32],
            guardian_measurement_root: [66u8; 32],
            guardian_checkpoint_root: [67u8; 32],
        };
        let evidence_hash =
            canonical_asymptote_observer_observation_request_hash(&request).unwrap();
        let challenge = AsymptoteObserverChallenge {
            challenge_id: [68u8; 32],
            epoch: 7,
            height: 12,
            view: 3,
            kind: AsymptoteObserverChallengeKind::TranscriptMismatch,
            challenger_account_id: observer,
            assignment: Some(assignment),
            observation_request: Some(request),
            transcript: None,
            canonical_close: None,
            evidence_hash,
            details: "observer rejected a malformed canonical observation request".into(),
        };

        let mut state = MockState::default();
        state
            .insert(
                VALIDATOR_SET_KEY,
                &write_validator_sets(&validator_sets(&[(21, 1), (22, 1), (23, 1)])).unwrap(),
            )
            .unwrap();

        with_ctx(|ctx| {
            run_async(registry.handle_service_call(
                &mut state,
                "report_asymptote_observer_challenge@v1",
                &codec::to_bytes_canonical(&challenge).unwrap(),
                ctx,
            ))
            .unwrap();
        });

        let quarantined: BTreeSet<AccountId> = codec::from_bytes_canonical(
            &state
                .get(QUARANTINED_VALIDATORS_KEY)
                .unwrap()
                .expect("quarantine set stored"),
        )
        .unwrap();
        assert!(quarantined.contains(&producer));
        assert!(!quarantined.contains(&observer));

        let stored_sets = read_validator_sets(
            &state
                .get(VALIDATOR_SET_KEY)
                .unwrap()
                .expect("validator sets stored"),
        )
        .unwrap();
        let next = stored_sets.next.expect("next validator set staged");
        assert!(!next
            .validators
            .iter()
            .any(|validator| validator.account_id == producer));
        assert!(next
            .validators
            .iter()
            .any(|validator| validator.account_id == observer));
    }

    #[test]
    fn invalid_canonical_close_challenge_blames_producer_and_remains_published_without_quarantine()
    {
        let registry = production_registry();
        let producer = AccountId([24u8; 32]);
        let observer = AccountId([25u8; 32]);
        let canonical_close = AsymptoteObserverCanonicalClose {
            epoch: 8,
            height: 13,
            view: 2,
            assignments_hash: [71u8; 32],
            transcripts_root: [72u8; 32],
            challenges_root: [73u8; 32],
            transcript_count: 1,
            challenge_count: 1,
            challenge_cutoff_timestamp_ms: 1_760_000_000,
        };
        let evidence_hash =
            canonical_asymptote_observer_canonical_close_hash(&canonical_close).unwrap();
        let challenge = AsymptoteObserverChallenge {
            challenge_id: [70u8; 32],
            epoch: 8,
            height: 13,
            view: 2,
            kind: AsymptoteObserverChallengeKind::InvalidCanonicalClose,
            challenger_account_id: producer,
            assignment: None,
            observation_request: None,
            transcript: None,
            canonical_close: Some(canonical_close),
            evidence_hash,
            details: "invalid proof-carried canonical close is challenge-dominated".into(),
        };
        let abort = AsymptoteObserverCanonicalAbort {
            epoch: 8,
            height: 13,
            view: 2,
            assignments_hash: [71u8; 32],
            transcripts_root: [72u8; 32],
            challenges_root: [73u8; 32],
            transcript_count: 1,
            challenge_count: 1,
            challenge_cutoff_timestamp_ms: 1_760_000_100,
        };

        let mut state = MockState::default();
        state
            .insert(
                VALIDATOR_SET_KEY,
                &write_validator_sets(&validator_sets(&[(24, 1), (25, 1)])).unwrap(),
            )
            .unwrap();

        with_ctx(|ctx| {
            run_async(registry.handle_service_call(
                &mut state,
                "report_asymptote_observer_challenge@v1",
                &codec::to_bytes_canonical(&challenge).unwrap(),
                ctx,
            ))
            .unwrap();
            run_async(registry.handle_service_call(
                &mut state,
                "publish_asymptote_observer_canonical_abort@v1",
                &codec::to_bytes_canonical(&abort).unwrap(),
                ctx,
            ))
            .unwrap();
        });

        assert!(state.get(QUARANTINED_VALIDATORS_KEY).unwrap().is_none());

        let stored_challenge = state
            .get(&guardian_registry_observer_challenge_key(
                8,
                13,
                2,
                &[70u8; 32],
            ))
            .unwrap()
            .expect("observer challenge stored");
        let restored_challenge: AsymptoteObserverChallenge =
            codec::from_bytes_canonical(&stored_challenge).unwrap();
        assert_eq!(restored_challenge, challenge);

        let stored_abort = state
            .get(&guardian_registry_observer_canonical_abort_key(8, 13, 2))
            .unwrap()
            .expect("canonical abort stored");
        let restored_abort: AsymptoteObserverCanonicalAbort =
            codec::from_bytes_canonical(&stored_abort).unwrap();
        assert_eq!(restored_abort, abort);

        let evidence_registry: BTreeSet<[u8; 32]> = codec::from_bytes_canonical(
            &state
                .get(EVIDENCE_REGISTRY_KEY)
                .unwrap()
                .expect("evidence registry stored"),
        )
        .unwrap();
        assert_eq!(evidence_registry.len(), 1);

        let stored_sets = read_validator_sets(
            &state
                .get(VALIDATOR_SET_KEY)
                .unwrap()
                .expect("validator sets stored"),
        )
        .unwrap();
        let next = stored_sets.next.expect("next validator set staged");
        assert_eq!(next.validators.len(), 1);
        assert!(!next
            .validators
            .iter()
            .any(|validator| validator.account_id == producer));
        assert!(next
            .validators
            .iter()
            .any(|validator| validator.account_id == observer));
    }

    #[test]
    fn invalid_canonical_close_challenge_remains_published_when_membership_updates_are_disabled() {
        let registry = production_registry_without_accountable_membership_updates();
        let producer = AccountId([26u8; 32]);
        let observer = AccountId([27u8; 32]);
        let canonical_close = AsymptoteObserverCanonicalClose {
            epoch: 8,
            height: 14,
            view: 1,
            assignments_hash: [76u8; 32],
            transcripts_root: [77u8; 32],
            challenges_root: [78u8; 32],
            transcript_count: 1,
            challenge_count: 1,
            challenge_cutoff_timestamp_ms: 1_760_000_200,
        };
        let challenge = AsymptoteObserverChallenge {
            challenge_id: [75u8; 32],
            epoch: 8,
            height: 14,
            view: 1,
            kind: AsymptoteObserverChallengeKind::InvalidCanonicalClose,
            challenger_account_id: observer,
            assignment: None,
            observation_request: None,
            transcript: None,
            canonical_close: Some(canonical_close.clone()),
            evidence_hash: canonical_asymptote_observer_canonical_close_hash(&canonical_close)
                .unwrap(),
            details: "negative sealing object remains decisive without membership penalties".into(),
        };

        let mut state = MockState::default();
        state
            .insert(
                VALIDATOR_SET_KEY,
                &write_validator_sets(&validator_sets(&[(26, 1), (27, 1), (28, 1)])).unwrap(),
            )
            .unwrap();

        with_ctx(|ctx| {
            run_async(registry.handle_service_call(
                &mut state,
                "report_asymptote_observer_challenge@v1",
                &codec::to_bytes_canonical(&challenge).unwrap(),
                ctx,
            ))
            .unwrap();
        });

        let stored_challenge: AsymptoteObserverChallenge = codec::from_bytes_canonical(
            &state
                .get(&guardian_registry_observer_challenge_key(
                    8,
                    14,
                    1,
                    &[75u8; 32],
                ))
                .unwrap()
                .expect("observer challenge stored"),
        )
        .unwrap();
        assert_eq!(stored_challenge, challenge);
        assert!(state.get(QUARANTINED_VALIDATORS_KEY).unwrap().is_none());

        let stored_sets = read_validator_sets(
            &state
                .get(VALIDATOR_SET_KEY)
                .unwrap()
                .expect("validator sets stored"),
        )
        .unwrap();
        assert!(stored_sets.next.is_none());
        assert!(stored_sets
            .current
            .validators
            .iter()
            .any(|validator| validator.account_id == producer));

        let evidence_registry: BTreeSet<[u8; 32]> = codec::from_bytes_canonical(
            &state
                .get(EVIDENCE_REGISTRY_KEY)
                .unwrap()
                .expect("evidence registry stored"),
        )
        .unwrap();
        assert_eq!(evidence_registry.len(), 1);
    }

    #[test]
    fn reporting_aft_omission_remains_published_when_membership_update_attempt_errors() {
        let registry = production_registry();
        let omission = OmissionProof {
            height: 16,
            offender_account_id: AccountId([41u8; 32]),
            tx_hash: [91u8; 32],
            bulletin_root: [92u8; 32],
            details: "ordering omission remains decisive even if penalty staging errors".into(),
        };

        let mut state = MockState::default();
        state
            .insert(VALIDATOR_SET_KEY, &[0xFF, 0x00, 0x01])
            .unwrap();

        with_ctx(|ctx| {
            run_async(registry.handle_service_call(
                &mut state,
                "report_aft_omission@v1",
                &codec::to_bytes_canonical(&omission).unwrap(),
                ctx,
            ))
            .unwrap();
        });

        let stored_omission: OmissionProof = codec::from_bytes_canonical(
            &state
                .get(&aft_omission_proof_key(omission.height, &omission.tx_hash))
                .unwrap()
                .expect("omission proof stored"),
        )
        .unwrap();
        assert_eq!(stored_omission, omission);

        let evidence_registry: BTreeSet<[u8; 32]> = codec::from_bytes_canonical(
            &state
                .get(EVIDENCE_REGISTRY_KEY)
                .unwrap()
                .expect("evidence registry stored"),
        )
        .unwrap();
        assert_eq!(evidence_registry.len(), 1);
    }

    #[test]
    fn reporting_observer_challenge_remains_published_when_membership_update_attempt_errors() {
        let registry = production_registry();
        let canonical_close = AsymptoteObserverCanonicalClose {
            epoch: 9,
            height: 17,
            view: 1,
            assignments_hash: [93u8; 32],
            transcripts_root: [94u8; 32],
            challenges_root: [95u8; 32],
            transcript_count: 1,
            challenge_count: 1,
            challenge_cutoff_timestamp_ms: 1_780_000_000,
        };
        let challenge = AsymptoteObserverChallenge {
            challenge_id: [96u8; 32],
            epoch: 9,
            height: 17,
            view: 1,
            kind: AsymptoteObserverChallengeKind::InvalidCanonicalClose,
            challenger_account_id: AccountId([42u8; 32]),
            assignment: None,
            observation_request: None,
            transcript: None,
            canonical_close: Some(canonical_close.clone()),
            evidence_hash: canonical_asymptote_observer_canonical_close_hash(&canonical_close)
                .unwrap(),
            details: "sealing abort remains decisive even if penalty staging errors".into(),
        };

        let mut state = MockState::default();
        state
            .insert(VALIDATOR_SET_KEY, &[0xFE, 0x00, 0x02])
            .unwrap();

        with_ctx(|ctx| {
            run_async(registry.handle_service_call(
                &mut state,
                "report_asymptote_observer_challenge@v1",
                &codec::to_bytes_canonical(&challenge).unwrap(),
                ctx,
            ))
            .unwrap();
        });

        let stored_challenge: AsymptoteObserverChallenge = codec::from_bytes_canonical(
            &state
                .get(&guardian_registry_observer_challenge_key(
                    9,
                    17,
                    1,
                    &[96u8; 32],
                ))
                .unwrap()
                .expect("observer challenge stored"),
        )
        .unwrap();
        assert_eq!(stored_challenge, challenge);

        let evidence_registry: BTreeSet<[u8; 32]> = codec::from_bytes_canonical(
            &state
                .get(EVIDENCE_REGISTRY_KEY)
                .unwrap()
                .expect("evidence registry stored"),
        )
        .unwrap();
        assert_eq!(evidence_registry.len(), 1);
    }

    #[test]
    fn accountable_fault_skips_immediate_quarantine_when_current_liveness_would_break() {
        let registry = production_registry();
        let offender = AccountId([31u8; 32]);
        let omission = OmissionProof {
            height: 15,
            offender_account_id: offender,
            tx_hash: [71u8; 32],
            bulletin_root: [72u8; 32],
            details: "objective omission proof for a two-validator set".into(),
        };

        let mut state = MockState::default();
        state
            .insert(
                VALIDATOR_SET_KEY,
                &write_validator_sets(&validator_sets(&[(31, 1), (32, 1)])).unwrap(),
            )
            .unwrap();

        with_ctx(|ctx| {
            run_async(registry.handle_service_call(
                &mut state,
                "report_aft_omission@v1",
                &codec::to_bytes_canonical(&omission).unwrap(),
                ctx,
            ))
            .unwrap();
        });

        assert!(state.get(QUARANTINED_VALIDATORS_KEY).unwrap().is_none());

        let stored_sets = read_validator_sets(
            &state
                .get(VALIDATOR_SET_KEY)
                .unwrap()
                .expect("validator sets stored"),
        )
        .unwrap();
        let next = stored_sets.next.expect("next validator set staged");
        assert_eq!(next.validators.len(), 1);
        assert!(!next
            .validators
            .iter()
            .any(|validator| validator.account_id == offender));
    }

    #[test]
    fn publishing_observer_canonical_sealing_artifacts_persists_registry_state() {
        let registry = production_registry();
        let transcript_commitment = AsymptoteObserverTranscriptCommitment {
            epoch: 7,
            height: 12,
            view: 3,
            assignments_hash: [1u8; 32],
            transcripts_root: [2u8; 32],
            transcript_count: 2,
        };
        let transcript = AsymptoteObserverTranscript {
            statement: AsymptoteObserverStatement {
                epoch: 7,
                assignment: AsymptoteObserverAssignment {
                    epoch: 7,
                    producer_account_id: AccountId([3u8; 32]),
                    height: 12,
                    view: 3,
                    round: 0,
                    observer_account_id: AccountId([4u8; 32]),
                },
                block_hash: [5u8; 32],
                guardian_manifest_hash: [6u8; 32],
                guardian_decision_hash: [7u8; 32],
                guardian_counter: 8,
                guardian_trace_hash: [9u8; 32],
                guardian_measurement_root: [10u8; 32],
                guardian_checkpoint_root: [11u8; 32],
                verdict: AsymptoteObserverVerdict::Ok,
                veto_kind: None,
                evidence_hash: [12u8; 32],
            },
            guardian_certificate: GuardianQuorumCertificate {
                manifest_hash: [13u8; 32],
                epoch: 7,
                decision_hash: [14u8; 32],
                ..Default::default()
            },
        };
        let challenge_commitment = AsymptoteObserverChallengeCommitment {
            epoch: 7,
            height: 12,
            view: 3,
            challenges_root: [15u8; 32],
            challenge_count: 1,
        };
        let evidence_hash = canonical_asymptote_observer_transcript_hash(&transcript).unwrap();
        let challenge = AsymptoteObserverChallenge {
            challenge_id: [16u8; 32],
            epoch: 7,
            height: 12,
            view: 3,
            kind: AsymptoteObserverChallengeKind::VetoTranscriptPresent,
            challenger_account_id: AccountId([17u8; 32]),
            assignment: Some(transcript.statement.assignment.clone()),
            observation_request: None,
            transcript: Some(transcript.clone()),
            canonical_close: None,
            evidence_hash,
            details: "published veto transcript dominates close".into(),
        };
        let abort = AsymptoteObserverCanonicalAbort {
            epoch: 7,
            height: 12,
            view: 3,
            assignments_hash: [19u8; 32],
            transcripts_root: [20u8; 32],
            challenges_root: [21u8; 32],
            transcript_count: 1,
            challenge_count: 1,
            challenge_cutoff_timestamp_ms: 1_750_000_100,
        };

        let mut state = MockState::default();
        with_ctx(|ctx| {
            run_async(registry.handle_service_call(
                &mut state,
                "publish_asymptote_observer_transcript_commitment@v1",
                &codec::to_bytes_canonical(&transcript_commitment).unwrap(),
                ctx,
            ))
            .unwrap();
            run_async(registry.handle_service_call(
                &mut state,
                "publish_asymptote_observer_transcript@v1",
                &codec::to_bytes_canonical(&transcript).unwrap(),
                ctx,
            ))
            .unwrap();
            run_async(registry.handle_service_call(
                &mut state,
                "publish_asymptote_observer_challenge_commitment@v1",
                &codec::to_bytes_canonical(&challenge_commitment).unwrap(),
                ctx,
            ))
            .unwrap();
            run_async(registry.handle_service_call(
                &mut state,
                "report_asymptote_observer_challenge@v1",
                &codec::to_bytes_canonical(&challenge).unwrap(),
                ctx,
            ))
            .unwrap();
            run_async(registry.handle_service_call(
                &mut state,
                "publish_asymptote_observer_canonical_abort@v1",
                &codec::to_bytes_canonical(&abort).unwrap(),
                ctx,
            ))
            .unwrap();
        });

        let stored_transcript_commitment = state
            .get(&guardian_registry_observer_transcript_commitment_key(
                7, 12, 3,
            ))
            .unwrap()
            .expect("transcript commitment stored");
        let restored_transcript_commitment: AsymptoteObserverTranscriptCommitment =
            codec::from_bytes_canonical(&stored_transcript_commitment).unwrap();
        assert_eq!(restored_transcript_commitment, transcript_commitment);

        let stored_transcript = state
            .get(&guardian_registry_observer_transcript_key(
                7,
                12,
                3,
                0,
                &AccountId([4u8; 32]),
            ))
            .unwrap()
            .expect("observer transcript stored");
        let restored_transcript: AsymptoteObserverTranscript =
            codec::from_bytes_canonical(&stored_transcript).unwrap();
        assert_eq!(restored_transcript, transcript);

        let stored_challenge_commitment = state
            .get(&guardian_registry_observer_challenge_commitment_key(
                7, 12, 3,
            ))
            .unwrap()
            .expect("challenge commitment stored");
        let restored_challenge_commitment: AsymptoteObserverChallengeCommitment =
            codec::from_bytes_canonical(&stored_challenge_commitment).unwrap();
        assert_eq!(restored_challenge_commitment, challenge_commitment);

        let stored_challenge = state
            .get(&guardian_registry_observer_challenge_key(
                7,
                12,
                3,
                &[16u8; 32],
            ))
            .unwrap()
            .expect("observer challenge stored");
        let restored_challenge: AsymptoteObserverChallenge =
            codec::from_bytes_canonical(&stored_challenge).unwrap();
        assert_eq!(restored_challenge, challenge);

        let stored_abort = state
            .get(&guardian_registry_observer_canonical_abort_key(7, 12, 3))
            .unwrap()
            .expect("canonical abort stored");
        let restored_abort: AsymptoteObserverCanonicalAbort =
            codec::from_bytes_canonical(&stored_abort).unwrap();
        assert_eq!(restored_abort, abort);
    }

    #[test]
    fn observer_canonical_abort_dominates_close_but_close_cannot_override_abort() {
        let registry = production_registry();
        let close = AsymptoteObserverCanonicalClose {
            epoch: 9,
            height: 22,
            view: 1,
            assignments_hash: [81u8; 32],
            transcripts_root: [82u8; 32],
            challenges_root: [83u8; 32],
            transcript_count: 1,
            challenge_count: 0,
            challenge_cutoff_timestamp_ms: 1_770_000_000,
        };
        let abort = AsymptoteObserverCanonicalAbort {
            epoch: 9,
            height: 22,
            view: 1,
            assignments_hash: [81u8; 32],
            transcripts_root: [82u8; 32],
            challenges_root: [84u8; 32],
            transcript_count: 1,
            challenge_count: 1,
            challenge_cutoff_timestamp_ms: 1_770_000_100,
        };

        let mut close_first_state = MockState::default();
        with_ctx(|ctx| {
            run_async(registry.handle_service_call(
                &mut close_first_state,
                "publish_asymptote_observer_canonical_close@v1",
                &codec::to_bytes_canonical(&close).unwrap(),
                ctx,
            ))
            .unwrap();
            run_async(registry.handle_service_call(
                &mut close_first_state,
                "publish_asymptote_observer_canonical_abort@v1",
                &codec::to_bytes_canonical(&abort).unwrap(),
                ctx,
            ))
            .unwrap();
        });
        assert!(close_first_state
            .get(&guardian_registry_observer_canonical_close_key(9, 22, 1))
            .unwrap()
            .is_none());
        let stored_abort: AsymptoteObserverCanonicalAbort = codec::from_bytes_canonical(
            &close_first_state
                .get(&guardian_registry_observer_canonical_abort_key(9, 22, 1))
                .unwrap()
                .expect("abort stored"),
        )
        .unwrap();
        assert_eq!(stored_abort, abort);

        let mut abort_first_state = MockState::default();
        with_ctx(|ctx| {
            run_async(registry.handle_service_call(
                &mut abort_first_state,
                "publish_asymptote_observer_canonical_abort@v1",
                &codec::to_bytes_canonical(&abort).unwrap(),
                ctx,
            ))
            .unwrap();
            let err = run_async(registry.handle_service_call(
                &mut abort_first_state,
                "publish_asymptote_observer_canonical_close@v1",
                &codec::to_bytes_canonical(&close).unwrap(),
                ctx,
            ))
            .unwrap_err();
            assert!(err
                .to_string()
                .contains("canonical abort is already persisted"));
        });
    }

    #[test]
    fn reporting_observer_challenge_materializes_challenge_commitment_and_abort_from_close() {
        let registry = production_registry();
        let close = AsymptoteObserverCanonicalClose {
            epoch: 11,
            height: 24,
            view: 2,
            assignments_hash: [101u8; 32],
            transcripts_root: [102u8; 32],
            challenges_root: [0u8; 32],
            transcript_count: 1,
            challenge_count: 0,
            challenge_cutoff_timestamp_ms: 1_780_000_500,
        };
        let challenge = AsymptoteObserverChallenge {
            challenge_id: [103u8; 32],
            epoch: 11,
            height: 24,
            view: 2,
            kind: AsymptoteObserverChallengeKind::InvalidCanonicalClose,
            challenger_account_id: AccountId([104u8; 32]),
            assignment: None,
            observation_request: None,
            transcript: None,
            canonical_close: Some(close.clone()),
            evidence_hash: canonical_asymptote_observer_canonical_close_hash(&close).unwrap(),
            details: "late challenge dominates previously published close".into(),
        };

        let mut state = MockState::default();
        with_ctx(|ctx| {
            run_async(registry.handle_service_call(
                &mut state,
                "publish_asymptote_observer_canonical_close@v1",
                &codec::to_bytes_canonical(&close).unwrap(),
                ctx,
            ))
            .unwrap();
            run_async(registry.handle_service_call(
                &mut state,
                "report_asymptote_observer_challenge@v1",
                &codec::to_bytes_canonical(&challenge).unwrap(),
                ctx,
            ))
            .unwrap();
        });

        assert!(state
            .get(&guardian_registry_observer_canonical_close_key(11, 24, 2))
            .unwrap()
            .is_none());
        let stored_commitment: AsymptoteObserverChallengeCommitment = codec::from_bytes_canonical(
            &state
                .get(&guardian_registry_observer_challenge_commitment_key(
                    11, 24, 2,
                ))
                .unwrap()
                .expect("challenge commitment stored"),
        )
        .unwrap();
        assert_eq!(stored_commitment.challenge_count, 1);
        let stored_abort: AsymptoteObserverCanonicalAbort = codec::from_bytes_canonical(
            &state
                .get(&guardian_registry_observer_canonical_abort_key(11, 24, 2))
                .unwrap()
                .expect("abort stored"),
        )
        .unwrap();
        assert_eq!(stored_abort.assignments_hash, close.assignments_hash);
        assert_eq!(stored_abort.transcripts_root, close.transcripts_root);
        assert_eq!(
            stored_abort.challenges_root,
            stored_commitment.challenges_root
        );
        assert_eq!(stored_abort.challenge_count, 1);
        assert_eq!(
            stored_abort.challenge_cutoff_timestamp_ms,
            close.challenge_cutoff_timestamp_ms
        );
    }

    #[test]
    fn canonical_observer_policy_requires_non_zero_challenge_window() {
        let registry = production_registry();
        let policy = AsymptotePolicy {
            epoch: 3,
            observer_rounds: 1,
            observer_committee_size: 1,
            observer_sealing_mode: AsymptoteObserverSealingMode::CanonicalChallengeV1,
            ..Default::default()
        };

        let mut state = MockState::default();
        let mut err = None;
        with_ctx(|ctx| {
            err = Some(
                run_async(registry.handle_service_call(
                    &mut state,
                    "publish_asymptote_policy@v1",
                    &codec::to_bytes_canonical(&policy).unwrap(),
                    ctx,
                ))
                .unwrap_err(),
            );
        });
        let err = err.expect("policy publication should fail");

        assert!(err
            .to_string()
            .contains("canonical observer sealing mode requires a non-zero challenge window"));
    }
}
