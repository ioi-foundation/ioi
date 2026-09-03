// Path: crates/validator/src/standard/orchestration/finalize.rs

use super::aft_collapse::{
    derive_expected_aft_canonical_collapse_for_block, observe_live_committed_chain_through_block,
};
use super::consensus::{
    build_aft_pq_channel_configuration, recovered_consensus_header_stitch_segment_budget,
    recovered_consensus_header_stitch_window_budget, select_local_aft_vote_signer,
    LocalAftVoteSigner, AFT_RECOVERED_CONSENSUS_HEADER_STITCH_OVERLAP,
    AFT_RECOVERED_CONSENSUS_HEADER_WINDOW,
};
use anyhow::{anyhow, Result};
use ioi_api::{
    chain::{StateRef, WorkloadClientApi},
    commitment::CommitmentScheme,
    consensus::ConsensusEngine,
    crypto::{SerializableKey, SigningKeyPair},
    state::{StateManager, Verifier},
};
use ioi_crypto::sign::dilithium::MldsaKeyPair;
// REMOVED: use ioi_client::WorkloadClient;
#[cfg(test)]
use ioi_ipc::public::TxStatus;
use ioi_networking::libp2p::{pq_channel::PqPeerEnrollment, SwarmCommand};
use ioi_networking::traits::NodeState;
use ioi_types::{
    app::{
        account_id_from_key_material, aft_archived_recovered_history_checkpoint_key,
        aft_archived_recovered_history_profile_activation_hash_key,
        aft_archived_recovered_history_profile_activation_key,
        aft_archived_recovered_history_retention_receipt_key,
        aft_archived_recovered_history_segment_key, aft_archived_recovered_restart_page_key,
        aft_missing_recovery_share_key, aft_recovered_publication_bundle_key,
        aft_recovery_capsule_key, aft_recovery_share_material_key, aft_recovery_share_receipt_key,
        archived_recovered_history_retained_through_height,
        archived_recovered_restart_page_range_for_profile,
        build_archived_recovered_history_checkpoint, build_archived_recovered_history_profile,
        build_archived_recovered_history_profile_activation,
        build_archived_recovered_history_retention_receipt,
        build_archived_recovered_history_segment, build_archived_recovered_restart_page,
        build_publication_frontier,
        build_single_member_committed_surface_canonical_order_certificate,
        canonical_archived_recovered_history_checkpoint_hash,
        canonical_archived_recovered_history_profile_activation_hash,
        canonical_archived_recovered_history_profile_hash,
        canonical_archived_recovered_history_retention_receipt_hash,
        canonical_asymptote_observer_assignments_hash,
        canonical_asymptote_observer_canonical_close_hash,
        canonical_asymptote_observer_challenges_hash,
        canonical_asymptote_observer_transcripts_hash, canonical_bulletin_close_hash,
        canonical_order_publication_bundle_hash, canonical_recoverable_slot_payload_v4_hash,
        canonical_recoverable_slot_payload_v5_hash, canonical_recovery_capsule_hash,
        canonical_sealed_finality_proof_signing_bytes, canonical_validator_sets_hash,
        derive_asymptote_observer_plan_entries, derive_canonical_order_execution_object,
        derive_guardian_witness_assignment, derive_guardian_witness_assignments,
        derive_guardian_witness_assignments_for_strata,
        derive_recovery_witness_certificate_for_header, effective_set_for_height,
        guardian_registry_asymptote_policy_key, guardian_registry_committee_account_key,
        guardian_registry_committee_key, guardian_registry_witness_key,
        guardian_registry_witness_seed_key, guardian_registry_witness_set_key,
        normalize_recovered_publication_bundle_supporting_witnesses, read_validator_sets,
        recover_canonical_order_artifact_surface_from_share_materials,
        recover_full_canonical_order_surface_from_share_materials,
        recovered_canonical_header_entry, recovered_certified_header_entry,
        recovered_restart_block_header_entry,
        set_canonical_collapse_archived_recovered_history_anchor, to_root_hash,
        validate_archived_recovered_history_profile, AccountId, ArchivedRecoveredHistoryCheckpoint,
        ArchivedRecoveredHistoryCheckpointUpdateRule, ArchivedRecoveredHistoryProfile,
        ArchivedRecoveredHistoryProfileActivation, ArchivedRecoveredHistoryRetentionReceipt,
        ArchivedRecoveredHistorySegment, ArchivedRecoveredRestartPage,
        AssignedRecoveryShareEnvelopeV1, AsymptoteObserverCanonicalAbort,
        AsymptoteObserverCanonicalClose, AsymptoteObserverChallenge,
        AsymptoteObserverChallengeCommitment, AsymptoteObserverChallengeKind,
        AsymptoteObserverSealingMode, AsymptoteObserverStatement, AsymptoteObserverTranscript,
        AsymptoteObserverTranscriptCommitment, AsymptotePolicy, Block, BlockHeader,
        CanonicalCollapseObject, CanonicalOrderAbort, CanonicalOrderExecutionObject,
        CanonicalOrderPublicationBundle, ChainTransaction, ConsensusVote,
        GuardianCommitteeManifest, GuardianLogCheckpoint, GuardianWitnessAssignment,
        GuardianWitnessCommitteeManifest, GuardianWitnessEpochSeed, GuardianWitnessFaultEvidence,
        GuardianWitnessFaultKind, GuardianWitnessRecoveryBinding, GuardianWitnessSet,
        PublicationFrontier, RecoverableSlotPayloadV3, RecoverableSlotPayloadV5,
        RecoveredPublicationBundle, RecoveryCapsule, RecoveryCodingDescriptor,
        RecoveryCodingFamily, RecoveryShareMaterial, RecoveryShareReceipt, SealedFinalityProof,
        SignHeader, SignatureBundle, SignatureProof, SignatureSuite, StateEntry, SystemPayload,
        SystemTransaction, AFT_ACTIVE_ARCHIVED_RECOVERED_HISTORY_PROFILE_KEY,
        AFT_LATEST_ARCHIVED_RECOVERED_HISTORY_PROFILE_ACTIVATION_KEY,
        AFT_RECOVERED_PUBLICATION_BUNDLE_PREFIX,
    },
    codec,
    config::AftSafetyMode,
    keys::{ACCOUNT_NONCE_PREFIX, CURRENT_EPOCH_KEY, VALIDATOR_SET_KEY},
};
use parity_scale_codec::{Decode, Encode};
use serde::Serialize;
use std::collections::{BTreeMap, HashSet};
use std::fmt::Debug;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, Mutex};

use crate::common::GuardianSigner;
use crate::standard::orchestration::context::MainLoopContext;
use crate::standard::orchestration::mempool::{AddResult, Mempool};
#[cfg(test)]
use ioi_types::app::{
    archived_recovered_restart_page_range,
    recover_canonical_order_publication_bundle_from_share_materials,
};

const DEFAULT_AFT_ARCHIVED_RECOVERED_HISTORY_RETENTION_HORIZON: u64 = 1024;

const AFT_PQ_HEADER_AUTHORITY_V1_DOMAIN: &[u8] = b"ioi/aft/pq-header-authority/v1";

/// Issues the normative PQ producer signature directly from the rooted
/// ML-DSA key. Guardian counters and certificates are policy evidence in this
/// profile; they are not an authority prerequisite for Classic-BFT safety or
/// liveness.
fn issue_pq_header_authority_bundle(
    keypair: &MldsaKeyPair,
    header: &BlockHeader,
    preimage_hash: [u8; 32],
) -> Result<SignatureBundle> {
    if header.producer_key_suite != SignatureSuite::ML_DSA_44 {
        return Err(anyhow!(
            "PQ header authority requires an ML-DSA-44 producer suite"
        ));
    }
    let public_key = keypair.public_key().to_bytes();
    if public_key != header.producer_pubkey {
        return Err(anyhow!(
            "configured ML-DSA signer does not match the block producer public key"
        ));
    }
    let key_hash = account_id_from_key_material(SignatureSuite::ML_DSA_44, &public_key)?;
    if key_hash != header.producer_pubkey_hash {
        return Err(anyhow!(
            "configured ML-DSA signer does not match the block producer key hash"
        ));
    }

    // These legacy header fields remain signed for wire compatibility. Zero
    // explicitly means that no guardian monotonic-counter claim is made. The
    // trace commits the suite-bound authority context and is not represented
    // as a guardian trace.
    let counter: u64 = 0;
    let mut authority_context =
        Vec::with_capacity(AFT_PQ_HEADER_AUTHORITY_V1_DOMAIN.len() + 32 + 32 + 8 + 8);
    authority_context.extend_from_slice(AFT_PQ_HEADER_AUTHORITY_V1_DOMAIN);
    authority_context.extend_from_slice(header.producer_account_id.as_ref());
    authority_context.extend_from_slice(&header.producer_pubkey_hash);
    authority_context.extend_from_slice(&header.height.to_be_bytes());
    authority_context.extend_from_slice(&header.view.to_be_bytes());
    let trace_hash = ioi_crypto::algorithms::hash::sha256(&authority_context)?;

    let mut signed_payload = Vec::with_capacity(72);
    signed_payload.extend_from_slice(&preimage_hash);
    signed_payload.extend_from_slice(&counter.to_be_bytes());
    signed_payload.extend_from_slice(&trace_hash);
    let signature = keypair.sign(&signed_payload)?.to_bytes();
    Ok(SignatureBundle {
        signature,
        counter,
        trace_hash,
        guardian_certificate: None,
        sealed_finality_proof: None,
    })
}

mod archived_history;
mod post_commit;
mod publication;
#[cfg(test)]
mod tests;

use self::archived_history::*;
pub use self::post_commit::finalize_and_broadcast_block;
pub(crate) use self::post_commit::schedule_committed_block_vote_replays;
use self::publication::*;
