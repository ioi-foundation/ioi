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
    aft_bulletin_availability_certificate_key, aft_bulletin_commitment_key,
    aft_bulletin_custody_assignment_key, aft_bulletin_custody_receipt_key,
    aft_bulletin_custody_response_key, aft_bulletin_entry_key,
    aft_bulletin_reconstruction_abort_key, aft_bulletin_reconstruction_certificate_key,
    aft_bulletin_retrievability_challenge_key, aft_bulletin_retrievability_profile_key,
    aft_bulletin_shard_manifest_key, aft_canonical_bulletin_close_key,
    aft_canonical_collapse_object_key, aft_canonical_order_abort_key,
    aft_missing_recovery_share_key, aft_omission_proof_key, aft_order_certificate_key,
    aft_publication_frontier_contradiction_key, aft_publication_frontier_key,
    aft_recovered_publication_bundle_key, aft_recovered_publication_bundle_prefix,
    aft_recovery_capsule_key, aft_recovery_share_material_key, aft_recovery_share_material_prefix,
    aft_recovery_share_receipt_key, aft_recovery_share_receipt_prefix,
    aft_recovery_witness_certificate_key, bind_canonical_collapse_continuity,
    build_archived_recovered_history_checkpoint, build_archived_recovered_history_profile,
    build_archived_recovered_history_profile_activation,
    build_archived_recovered_history_retention_receipt, build_archived_recovered_restart_page,
    build_bulletin_custody_assignment, build_bulletin_custody_response,
    build_bulletin_reconstruction_abort, build_bulletin_reconstruction_certificate,
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
    effective_set_for_height, evidence_id, extract_endogenous_canonical_bulletin_surface,
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
    validate_archived_recovered_restart_page_against_profile, validate_bulletin_custody_assignment,
    validate_bulletin_custody_receipt, validate_bulletin_custody_response,
    validate_bulletin_retrievability_challenge, validate_bulletin_retrievability_profile,
    validate_bulletin_shard_manifest, validate_recovered_page_coverage,
    verify_canonical_collapse_continuity, verify_canonical_order_publication_bundle,
    verify_publication_frontier_contradiction, write_validator_sets, AccountId,
    AftHistoricalRetrievabilitySurface, AftRecoveredStateSurface,
    ArchivedRecoveredHistoryCheckpoint, ArchivedRecoveredHistoryProfile,
    ArchivedRecoveredHistoryProfileActivation, ArchivedRecoveredHistoryRetentionReceipt,
    ArchivedRecoveredHistorySegment, ArchivedRecoveredRestartPage, AsymptoteObserverCanonicalAbort,
    AsymptoteObserverCanonicalClose, AsymptoteObserverChallenge,
    AsymptoteObserverChallengeCommitment, AsymptoteObserverChallengeKind,
    AsymptoteObserverSealingMode, AsymptoteObserverTranscript,
    AsymptoteObserverTranscriptCommitment, AsymptotePolicy, BulletinAvailabilityCertificate,
    BulletinCommitment, BulletinCustodyAssignment, BulletinCustodyReceipt, BulletinCustodyResponse,
    BulletinReconstructionAbort, BulletinReconstructionCertificate,
    BulletinRetrievabilityChallenge, BulletinRetrievabilityProfile, BulletinShardManifest,
    BulletinSurfaceEntry, CanonicalBulletinClose, CanonicalCollapseKind, CanonicalCollapseObject,
    CanonicalOrderAbort, CanonicalOrderAbortReason, CanonicalOrderCertificate,
    CanonicalOrderPublicationBundle, CanonicalReplayPrefixEntry, CollapseState,
    EffectProofVerifierDescriptor, FailureReport, FinalityTier, GuardianCommitteeManifest,
    GuardianLogCheckpoint, GuardianMeasurementProfile, GuardianTransparencyLogDescriptor,
    GuardianWitnessCommitteeManifest, GuardianWitnessEpochSeed, GuardianWitnessFaultEvidence,
    GuardianWitnessSet, MissingRecoveryShare, OffenseFacts, OffenseType, OmissionProof,
    ProofOfDivergence, PublicationFrontier, PublicationFrontierContradiction,
    PublicationFrontierContradictionKind, RecoveredCanonicalHeaderEntry,
    RecoveredCertifiedHeaderEntry, RecoveredPublicationBundle, RecoveredRestartBlockHeaderEntry,
    RecoveredSegmentFoldPage, RecoveryCapsule, RecoveryShareMaterial, RecoveryShareReceipt,
    RecoveryWitnessCertificate, SealedEffectRecord,
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


mod archived_history;
mod materialize;
mod observer;
mod reads;
mod service;
mod validation;
#[cfg(test)]
mod tests;
