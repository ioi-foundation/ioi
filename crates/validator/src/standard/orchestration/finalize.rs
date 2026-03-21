// Path: crates/validator/src/standard/orchestration/finalize.rs

use super::aft_collapse::{
    derive_expected_aft_canonical_collapse_for_block,
    require_persisted_aft_canonical_collapse_if_needed,
};
use super::consensus::{
    recovered_consensus_header_stitch_segment_budget,
    recovered_consensus_header_stitch_window_budget, AFT_RECOVERED_CONSENSUS_HEADER_STITCH_OVERLAP,
    AFT_RECOVERED_CONSENSUS_HEADER_WINDOW,
};
use anyhow::{anyhow, Result};
use ioi_api::{
    chain::{StateRef, WorkloadClientApi},
    commitment::CommitmentScheme,
    consensus::ConsensusEngine,
    state::{StateManager, Verifier},
};
// REMOVED: use ioi_client::WorkloadClient;
use ioi_ipc::public::TxStatus;
use ioi_networking::libp2p::SwarmCommand;
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
        archived_recovered_history_retained_through_height, archived_recovered_restart_page_range,
        archived_recovered_restart_page_range_for_profile,
        build_archived_recovered_history_checkpoint, build_archived_recovered_history_profile,
        build_archived_recovered_history_profile_activation,
        build_archived_recovered_history_retention_receipt,
        build_archived_recovered_history_segment, build_archived_recovered_restart_page,
        build_committed_surface_canonical_order_certificate, build_publication_frontier,
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
        recover_canonical_order_publication_bundle_from_share_materials,
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
use crate::standard::orchestration::ingestion::ChainTipInfo;
use crate::standard::orchestration::mempool::{AddResult, Mempool};

const DEFAULT_AFT_ARCHIVED_RECOVERED_HISTORY_RETENTION_HORIZON: u64 = 1024;

fn default_archived_recovered_history_profile() -> Result<ArchivedRecoveredHistoryProfile> {
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

async fn load_active_archived_recovered_history_profile(
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

async fn load_latest_archived_recovered_history_profile_activation(
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

async fn load_archived_recovered_history_profile_activation_by_hash(
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

async fn load_latest_archived_recovered_history_checkpoint(
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

async fn load_archived_recovered_history_retention_receipt(
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

async fn resolve_archived_recovered_history_anchor_hashes(
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

async fn ensure_archived_recovered_history_profile(
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

fn relay_fanout() -> usize {
    std::env::var("IOI_AFT_TX_RELAY_FANOUT")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(1)
}

fn post_commit_leader_fanout() -> usize {
    std::env::var("IOI_AFT_POST_COMMIT_LEADER_FANOUT")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(1)
}

fn post_commit_relay_limit() -> usize {
    std::env::var("IOI_AFT_POST_COMMIT_RELAY_LIMIT")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(2048)
}

fn post_commit_direct_relay_limit() -> usize {
    std::env::var("IOI_AFT_POST_COMMIT_DIRECT_RELAY_LIMIT")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(256)
}

fn post_commit_rekick_delays_ms() -> Vec<u64> {
    std::env::var("IOI_AFT_POST_COMMIT_REKICK_DELAYS_MS")
        .ok()
        .map(|value| {
            value
                .split(',')
                .filter_map(|part| part.trim().parse::<u64>().ok())
                .filter(|delay| *delay > 0)
                .collect::<Vec<_>>()
        })
        .filter(|delays| !delays.is_empty())
        .unwrap_or_else(|| vec![100, 300, 750])
}

fn post_commit_vote_replay_delays_ms() -> Vec<u64> {
    std::env::var("IOI_AFT_POST_COMMIT_VOTE_REPLAY_DELAYS_MS")
        .ok()
        .map(|value| {
            value
                .split(',')
                .filter_map(|part| part.trim().parse::<u64>().ok())
                .filter(|delay| *delay > 0)
                .collect::<Vec<_>>()
        })
        .filter(|delays| !delays.is_empty())
        .unwrap_or_else(|| vec![150, 500, 1200])
}

#[derive(Debug, Clone)]
struct CanonicalObserverPublicationArtifacts {
    transcripts: Vec<AsymptoteObserverTranscript>,
    challenges: Vec<AsymptoteObserverChallenge>,
    transcript_commitment: AsymptoteObserverTranscriptCommitment,
    challenge_commitment: AsymptoteObserverChallengeCommitment,
    canonical_close: Option<AsymptoteObserverCanonicalClose>,
    canonical_abort: Option<AsymptoteObserverCanonicalAbort>,
}

#[derive(Debug, Clone)]
struct CanonicalOrderPublicationArtifacts {
    bundle: Option<CanonicalOrderPublicationBundle>,
    publication_frontier: Option<PublicationFrontier>,
    canonical_abort: Option<CanonicalOrderAbort>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ExperimentalRecoveryScaffoldArtifacts {
    capsule: RecoveryCapsule,
    share_commitment_hash: [u8; 32],
}

impl ExperimentalRecoveryScaffoldArtifacts {
    fn recovery_binding(&self) -> Result<GuardianWitnessRecoveryBinding> {
        Ok(GuardianWitnessRecoveryBinding {
            recovery_capsule_hash: canonical_recovery_capsule_hash(&self.capsule)
                .map_err(|error| anyhow!(error))?,
            share_commitment_hash: self.share_commitment_hash,
        })
    }
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq)]
struct ExperimentalMultiWitnessRecoverySharePlan {
    assignment: GuardianWitnessAssignment,
    share_index: u16,
    share_count: u16,
    recovery_threshold: u16,
    share_commitment_hash: [u8; 32],
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq)]
struct ExperimentalMultiWitnessRecoveryPlan {
    payload_commitment_hash: [u8; 32],
    recovery_committee_root_hash: [u8; 32],
    coding_root_hash: [u8; 32],
    recovery_window_close_ms: u64,
    coding: RecoveryCodingDescriptor,
    share_count: u16,
    recovery_threshold: u16,
    data_shard_count: u16,
    parity_shard_count: u16,
    shares: Vec<ExperimentalMultiWitnessRecoverySharePlan>,
}

#[derive(Clone)]
struct GuardianRegistryPublisher {
    workload_client: Arc<dyn WorkloadClientApi>,
    tx_pool: Arc<Mempool>,
    consensus_kick_tx: mpsc::UnboundedSender<()>,
    nonce_manager: Arc<Mutex<BTreeMap<AccountId, u64>>>,
    local_keypair: libp2p::identity::Keypair,
    chain_id: ioi_types::app::ChainId,
}

fn local_account_id_from_keypair(local_keypair: &libp2p::identity::Keypair) -> Result<AccountId> {
    Ok(AccountId(account_id_from_key_material(
        SignatureSuite::ED25519,
        &local_keypair.public().encode_protobuf(),
    )?))
}

const EXPERIMENTAL_RECOVERY_SCAFFOLD_WINDOW_MS: u64 = 60_000;
const EXPERIMENTAL_SYSTEMATIC_XOR_MIN_SHARE_COUNT: u16 = 3;
const EXPERIMENTAL_SYSTEMATIC_GF256_MIN_SHARE_COUNT: u16 = 4;
const EXPERIMENTAL_SYSTEMATIC_GF256_MIN_PARITY_SHARDS: u16 = 2;

fn hash_experimental_recovery_scaffold_component<T: Encode>(
    domain: &'static [u8],
    value: &T,
) -> Result<[u8; 32]> {
    let bytes = encode_experimental_recovery_component(domain, value)?;
    ioi_crypto::algorithms::hash::sha256(&bytes).map_err(|e| anyhow!(e))
}

fn encode_experimental_recovery_component<T: Encode>(
    domain: &'static [u8],
    value: &T,
) -> Result<Vec<u8>> {
    codec::to_bytes_canonical(&(domain.to_vec(), value)).map_err(|e| anyhow!(e))
}

fn canonical_block_commitment_hash(header: &BlockHeader) -> Result<[u8; 32]> {
    let hash = header.hash().map_err(|error| anyhow!(error))?;
    hash.as_slice()
        .try_into()
        .map_err(|_| anyhow!("block header hash must be 32 bytes"))
}

fn experimental_multi_witness_coding(
    share_count: u16,
    recovery_threshold: u16,
) -> RecoveryCodingDescriptor {
    if share_count >= EXPERIMENTAL_SYSTEMATIC_GF256_MIN_SHARE_COUNT
        && share_count
            >= recovery_threshold.saturating_add(EXPERIMENTAL_SYSTEMATIC_GF256_MIN_PARITY_SHARDS)
    {
        RecoveryCodingDescriptor {
            family: RecoveryCodingFamily::SystematicGf256KOfNV1,
            share_count,
            recovery_threshold,
        }
    } else if share_count >= EXPERIMENTAL_SYSTEMATIC_XOR_MIN_SHARE_COUNT
        && share_count == recovery_threshold.saturating_add(1)
    {
        RecoveryCodingDescriptor {
            family: RecoveryCodingFamily::SystematicXorKOfKPlus1V1,
            share_count,
            recovery_threshold,
        }
    } else {
        RecoveryCodingDescriptor {
            family: RecoveryCodingFamily::TransparentCommittedSurfaceV1,
            share_count,
            recovery_threshold,
        }
    }
}

fn experimental_multi_witness_parity_threshold(share_count: u16) -> Option<u16> {
    (share_count >= EXPERIMENTAL_SYSTEMATIC_XOR_MIN_SHARE_COUNT).then_some(share_count - 1)
}

fn experimental_multi_witness_parity_threshold_for_len(share_count: usize) -> Option<u16> {
    u16::try_from(share_count)
        .ok()
        .and_then(experimental_multi_witness_parity_threshold)
}

fn ordered_transaction_bytes(transactions: &[ChainTransaction]) -> Result<Vec<Vec<u8>>> {
    transactions
        .iter()
        .map(|transaction| codec::to_bytes_canonical(transaction).map_err(|error| anyhow!(error)))
        .collect()
}

fn build_recoverable_slot_payload_v3_publication_bundle_bytes(
    header: &BlockHeader,
    transactions: &[ChainTransaction],
    certificate: &ioi_types::app::CanonicalOrderCertificate,
) -> Result<Vec<u8>> {
    let mut publication_header = header.clone();
    publication_header.canonical_order_certificate = Some(certificate.clone());
    let execution_object =
        derive_canonical_order_execution_object(&publication_header, transactions).map_err(
            |abort| {
                anyhow!(
                    "failed to derive recoverable publication bundle: {}",
                    abort.details
                )
            },
        )?;
    let publication_bundle = build_canonical_order_publication_bundle(&execution_object);
    codec::to_bytes_canonical(&publication_bundle).map_err(|error| anyhow!(error))
}

fn build_recoverable_slot_payload_v3(
    header: &BlockHeader,
    transactions: &[ChainTransaction],
    certificate: &ioi_types::app::CanonicalOrderCertificate,
) -> Result<RecoverableSlotPayloadV3> {
    Ok(RecoverableSlotPayloadV3 {
        height: header.height,
        view: header.view,
        producer_account_id: header.producer_account_id,
        block_commitment_hash: canonical_block_commitment_hash(header)?,
        parent_block_hash: header.parent_hash,
        canonical_order_certificate: certificate.clone(),
        ordered_transaction_bytes: ordered_transaction_bytes(transactions)?,
        canonical_order_publication_bundle_bytes:
            build_recoverable_slot_payload_v3_publication_bundle_bytes(
                header,
                transactions,
                certificate,
            )?,
    })
}

fn build_recoverable_slot_payload_v4(
    header: &BlockHeader,
    transactions: &[ChainTransaction],
    certificate: &ioi_types::app::CanonicalOrderCertificate,
) -> Result<ioi_types::app::RecoverableSlotPayloadV4> {
    let payload_v3 = build_recoverable_slot_payload_v3(header, transactions, certificate)?;
    let (payload_v4, _, _) = ioi_types::app::lift_recoverable_slot_payload_v3_to_v4(&payload_v3)
        .map_err(|error| anyhow!(error))?;
    Ok(payload_v4)
}

#[cfg_attr(not(test), allow(dead_code))]
fn build_recoverable_slot_payload_v5(
    header: &BlockHeader,
    transactions: &[ChainTransaction],
    certificate: &ioi_types::app::CanonicalOrderCertificate,
) -> Result<RecoverableSlotPayloadV5> {
    let payload_v4 = build_recoverable_slot_payload_v4(header, transactions, certificate)?;
    let (payload_v5, _, _, _) = ioi_types::app::lift_recoverable_slot_payload_v4_to_v5(&payload_v4)
        .map_err(|error| anyhow!(error))?;
    Ok(payload_v5)
}

fn recovery_coding_uses_recoverable_payload(coding: RecoveryCodingDescriptor) -> bool {
    coding
        .family_contract()
        .map(|contract| contract.uses_recoverable_payload())
        .unwrap_or(false)
}

fn encode_coded_recovery_shards(
    coding: RecoveryCodingDescriptor,
    payload_bytes: &[u8],
) -> Result<Vec<Vec<u8>>> {
    ioi_types::app::encode_coded_recovery_shards(coding, payload_bytes)
        .map_err(|error| anyhow!(error))
}

#[cfg_attr(not(test), allow(dead_code))]
fn recover_recoverable_slot_payload_v3_from_share_materials(
    materials: &[RecoveryShareMaterial],
) -> Result<RecoverableSlotPayloadV3> {
    ioi_types::app::recover_recoverable_slot_payload_v3_from_share_materials(materials)
        .map_err(|error| anyhow!(error))
}

fn build_experimental_transparent_share_material_bytes(
    plan: &ExperimentalMultiWitnessRecoveryPlan,
    share: &ExperimentalMultiWitnessRecoverySharePlan,
    certificate: &ioi_types::app::CanonicalOrderCertificate,
) -> Result<Vec<u8>> {
    encode_experimental_recovery_component(
        b"aft::recovery::multi_witness::share_commitment::v1",
        &(
            plan.coding_root_hash,
            &share.assignment,
            share.share_index,
            share.share_count,
            share.recovery_threshold,
            plan.payload_commitment_hash,
            certificate.bulletin_commitment.bulletin_root,
            certificate.ordered_transactions_root_hash,
            certificate.resulting_state_root_hash,
        ),
    )
}

fn build_experimental_coded_share_commitment_hash(
    plan: &ExperimentalMultiWitnessRecoveryPlan,
    assignment: &GuardianWitnessAssignment,
    share_index: u16,
    shard_bytes: &[u8],
    coding: RecoveryCodingDescriptor,
) -> Result<[u8; 32]> {
    let domain = coding
        .family_contract()
        .map_err(|error| anyhow!(error))?
        .coded_share_commitment_domain()
        .map_err(|error| anyhow!(error))?;
    hash_experimental_recovery_scaffold_component(
        domain,
        &(
            plan.coding_root_hash,
            assignment,
            share_index,
            coding.share_count,
            coding.recovery_threshold,
            plan.payload_commitment_hash,
            shard_bytes,
        ),
    )
}

fn build_experimental_multi_witness_share_commitment_hash(
    plan: &ExperimentalMultiWitnessRecoveryPlan,
    assignment: &GuardianWitnessAssignment,
    share_index: u16,
    coding: RecoveryCodingDescriptor,
    certificate: &ioi_types::app::CanonicalOrderCertificate,
    coded_shards: Option<&Vec<Vec<u8>>>,
) -> Result<[u8; 32]> {
    let contract = coding.family_contract().map_err(|error| anyhow!(error))?;
    if contract.uses_recoverable_payload() {
        let shard_bytes = coded_shards
            .ok_or_else(|| anyhow!("coded recovery shards were not initialized"))?
            .get(usize::from(share_index))
            .ok_or_else(|| anyhow!("coded recovery share index exceeds shard set"))?;
        build_experimental_coded_share_commitment_hash(
            plan,
            assignment,
            share_index,
            shard_bytes,
            coding,
        )
    } else if coding.is_transparent_committed_surface() {
        hash_experimental_recovery_scaffold_component(
            b"aft::recovery::multi_witness::share_commitment::v1",
            &(
                plan.coding_root_hash,
                assignment,
                share_index,
                plan.share_count,
                plan.recovery_threshold,
                plan.payload_commitment_hash,
                certificate.bulletin_commitment.bulletin_root,
                certificate.ordered_transactions_root_hash,
                certificate.resulting_state_root_hash,
            ),
        )
    } else {
        Err(anyhow!(
            "multi-witness recovery plan does not support deterministic scaffold coding"
        ))
    }
}

fn materialize_experimental_multi_witness_share_material_bytes(
    plan: &ExperimentalMultiWitnessRecoveryPlan,
    share: &ExperimentalMultiWitnessRecoverySharePlan,
    certificate: &ioi_types::app::CanonicalOrderCertificate,
    coded_shards: Option<&Vec<Vec<u8>>>,
) -> Result<Vec<u8>> {
    let contract = plan
        .coding
        .family_contract()
        .map_err(|error| anyhow!(error))?;
    if contract.uses_recoverable_payload() {
        coded_shards
            .ok_or_else(|| anyhow!("coded recovery shards were not initialized"))?
            .get(usize::from(share.share_index))
            .cloned()
            .ok_or_else(|| anyhow!("coded recovery share index exceeds shard set"))
    } else if plan.coding.is_transparent_committed_surface() {
        build_experimental_transparent_share_material_bytes(plan, share, certificate)
    } else {
        Err(anyhow!(
            "multi-witness recovery share materialization does not support deterministic scaffolds"
        ))
    }
}

fn materialize_experimental_multi_witness_recovery_share_materials_from_plan(
    header: &BlockHeader,
    transactions: &[ChainTransaction],
    plan: &ExperimentalMultiWitnessRecoveryPlan,
) -> Result<Vec<RecoveryShareMaterial>> {
    let certificate = build_committed_surface_canonical_order_certificate(header, transactions)
        .map_err(|error| anyhow!(error))?;
    let block_commitment_hash = canonical_block_commitment_hash(header)?;
    let recoverable_payload = recovery_coding_uses_recoverable_payload(plan.coding)
        .then(|| build_recoverable_slot_payload_v3(header, transactions, &certificate))
        .transpose()?;
    let coded_shards = recoverable_payload
        .as_ref()
        .map(codec::to_bytes_canonical)
        .transpose()
        .map_err(|error| anyhow!(error))?
        .map(|payload_bytes| encode_coded_recovery_shards(plan.coding, &payload_bytes))
        .transpose()?;

    plan.shares
        .iter()
        .map(|share| {
            let material_bytes = materialize_experimental_multi_witness_share_material_bytes(
                plan,
                share,
                &certificate,
                coded_shards.as_ref(),
            )?;
            Ok(RecoveryShareMaterial {
                height: header.height,
                witness_manifest_hash: share.assignment.manifest_hash,
                block_commitment_hash,
                coding: plan.coding,
                share_index: share.share_index,
                share_commitment_hash: share.share_commitment_hash,
                material_bytes,
            })
        })
        .collect()
}

#[cfg_attr(not(test), allow(dead_code))]
fn build_experimental_multi_witness_recovery_share_materials(
    header: &BlockHeader,
    transactions: &[ChainTransaction],
    witness_seed: &GuardianWitnessEpochSeed,
    witness_set: &GuardianWitnessSet,
    reassignment_depth: u8,
    share_count: u16,
    recovery_threshold: u16,
) -> Result<Vec<RecoveryShareMaterial>> {
    let plan = build_experimental_multi_witness_recovery_plan(
        header,
        transactions,
        witness_seed,
        witness_set,
        reassignment_depth,
        share_count,
        recovery_threshold,
    )?;
    materialize_experimental_multi_witness_recovery_share_materials_from_plan(
        header,
        transactions,
        &plan,
    )
}

#[cfg_attr(not(test), allow(dead_code))]
fn verify_experimental_multi_witness_recovery_share_material(
    header: &BlockHeader,
    transactions: &[ChainTransaction],
    witness_seed: &GuardianWitnessEpochSeed,
    witness_set: &GuardianWitnessSet,
    reassignment_depth: u8,
    material: &RecoveryShareMaterial,
) -> Result<ioi_types::app::RecoveryShareReceipt> {
    if material.height != header.height {
        return Err(anyhow!(
            "recovery share material height does not match the bound block header"
        ));
    }

    let expected_block_commitment_hash = canonical_block_commitment_hash(header)?;
    if material.block_commitment_hash != expected_block_commitment_hash {
        return Err(anyhow!(
            "recovery share material block commitment does not match the bound block header"
        ));
    }

    let expected = build_experimental_multi_witness_recovery_share_materials(
        header,
        transactions,
        witness_seed,
        witness_set,
        reassignment_depth,
        material.coding.share_count,
        material.coding.recovery_threshold,
    )?
    .into_iter()
    .find(|candidate| {
        candidate.witness_manifest_hash == material.witness_manifest_hash
            && candidate.share_index == material.share_index
    })
    .ok_or_else(|| anyhow!("recovery share material is not assigned in the deterministic plan"))?;

    if expected != *material {
        return Err(anyhow!(
            "recovery share material does not match the deterministic committed-surface materialization"
        ));
    }

    Ok(material.to_recovery_share_receipt())
}

fn build_experimental_recovery_scaffold_artifacts(
    header: &BlockHeader,
    transactions: &[ChainTransaction],
    witness_manifest_hash: [u8; 32],
    reassignment_depth: u8,
) -> Result<ExperimentalRecoveryScaffoldArtifacts> {
    if witness_manifest_hash == [0u8; 32] {
        return Err(anyhow!(
            "experimental recovery scaffold requires a non-zero witness manifest hash"
        ));
    }

    let certificate = build_committed_surface_canonical_order_certificate(header, transactions)
        .map_err(|error| anyhow!(error))?;
    // Reuse the committed-surface recoverability root as the shared payload seed.
    // It does not carry witness/coding semantics on its own; the scaffold layers
    // those semantics above it with witness-local commitments.
    let payload_commitment_hash = certificate
        .bulletin_availability_certificate
        .recoverability_root;
    let recovery_window_close_ms = header
        .timestamp_ms_or_legacy()
        .saturating_add(EXPERIMENTAL_RECOVERY_SCAFFOLD_WINDOW_MS);
    let recovery_committee_root_hash = hash_experimental_recovery_scaffold_component(
        b"aft::recovery::scaffold::committee_root::v1",
        &(
            header.height,
            header.view,
            witness_manifest_hash,
            reassignment_depth,
        ),
    )?;
    let coding_root_hash = hash_experimental_recovery_scaffold_component(
        b"aft::recovery::scaffold::coding_root::v1",
        &(
            payload_commitment_hash,
            certificate.ordered_transactions_root_hash,
            certificate.resulting_state_root_hash,
            witness_manifest_hash,
            reassignment_depth,
            recovery_window_close_ms,
        ),
    )?;
    let capsule = RecoveryCapsule {
        height: header.height,
        coding: RecoveryCodingDescriptor::deterministic_scaffold(),
        recovery_committee_root_hash,
        payload_commitment_hash,
        coding_root_hash,
        recovery_window_close_ms,
    };
    let share_commitment_hash = hash_experimental_recovery_scaffold_component(
        b"aft::recovery::scaffold::share_commitment::v1",
        &(
            canonical_recovery_capsule_hash(&capsule).map_err(|error| anyhow!(error))?,
            witness_manifest_hash,
            reassignment_depth,
            header.producer_account_id,
            certificate.bulletin_commitment.bulletin_root,
            certificate.ordered_transactions_root_hash,
            certificate.resulting_state_root_hash,
        ),
    )?;

    Ok(ExperimentalRecoveryScaffoldArtifacts {
        capsule,
        share_commitment_hash,
    })
}

fn build_experimental_recovery_scaffold_share_receipt(
    header: &BlockHeader,
    certificate: &ioi_types::app::RecoveryWitnessCertificate,
) -> Result<RecoveryShareReceipt> {
    build_recovery_share_receipt_for_header(header, certificate)
}

fn build_recovery_share_receipt_for_header(
    header: &BlockHeader,
    certificate: &ioi_types::app::RecoveryWitnessCertificate,
) -> Result<RecoveryShareReceipt> {
    if certificate.height != header.height {
        return Err(anyhow!(
            "recovery witness certificate height does not match the bound block header"
        ));
    }

    Ok(RecoveryShareReceipt {
        height: header.height,
        witness_manifest_hash: certificate.witness_manifest_hash,
        block_commitment_hash: canonical_block_commitment_hash(header)?,
        share_commitment_hash: certificate.share_commitment_hash,
    })
}

fn build_experimental_multi_witness_recovery_plan_from_assignments(
    header: &BlockHeader,
    transactions: &[ChainTransaction],
    witness_epoch: u64,
    assignments: Vec<GuardianWitnessAssignment>,
    reassignment_depth: u8,
    recovery_threshold: u16,
) -> Result<ExperimentalMultiWitnessRecoveryPlan> {
    let share_count = u16::try_from(assignments.len())
        .map_err(|_| anyhow!("experimental multi-witness recovery plan exceeds u16 shares"))?;
    if share_count < 2 {
        return Err(anyhow!(
            "experimental multi-witness recovery plan requires at least two assigned witnesses"
        ));
    }
    if recovery_threshold < 2 {
        return Err(anyhow!(
            "experimental multi-witness recovery plan requires threshold at least two"
        ));
    }
    if recovery_threshold > share_count {
        return Err(anyhow!(
            "experimental multi-witness recovery threshold cannot exceed share count"
        ));
    }

    let certificate = build_committed_surface_canonical_order_certificate(header, transactions)
        .map_err(|error| anyhow!(error))?;
    let payload_commitment_hash = certificate
        .bulletin_availability_certificate
        .recoverability_root;
    let coding = experimental_multi_witness_coding(share_count, recovery_threshold);
    let recovery_window_close_ms = header
        .timestamp_ms_or_legacy()
        .saturating_add(EXPERIMENTAL_RECOVERY_SCAFFOLD_WINDOW_MS);
    let assigned_manifest_hashes = assignments
        .iter()
        .map(|assignment| assignment.manifest_hash)
        .collect::<Vec<_>>();
    let recovery_committee_root_hash = hash_experimental_recovery_scaffold_component(
        b"aft::recovery::multi_witness::committee_root::v1",
        &(
            witness_epoch,
            header.height,
            header.view,
            reassignment_depth,
            share_count,
            recovery_threshold,
            assigned_manifest_hashes,
        ),
    )?;
    let coding_root_hash = hash_experimental_recovery_scaffold_component(
        b"aft::recovery::multi_witness::coding_root::v1",
        &(
            payload_commitment_hash,
            certificate.ordered_transactions_root_hash,
            certificate.resulting_state_root_hash,
            recovery_committee_root_hash,
            coding,
            share_count,
            recovery_threshold,
            recovery_window_close_ms,
        ),
    )?;
    let recoverable_payload = recovery_coding_uses_recoverable_payload(coding)
        .then(|| build_recoverable_slot_payload_v3(header, transactions, &certificate))
        .transpose()?;
    let coded_shards = recoverable_payload
        .as_ref()
        .map(codec::to_bytes_canonical)
        .transpose()
        .map_err(|error| anyhow!(error))?
        .map(|payload_bytes| encode_coded_recovery_shards(coding, &payload_bytes))
        .transpose()?;
    let plan_stub = ExperimentalMultiWitnessRecoveryPlan {
        payload_commitment_hash,
        recovery_committee_root_hash,
        coding_root_hash,
        recovery_window_close_ms,
        coding,
        share_count,
        recovery_threshold,
        data_shard_count: recovery_threshold,
        parity_shard_count: share_count.saturating_sub(recovery_threshold),
        shares: Vec::new(),
    };
    let shares = assignments
        .into_iter()
        .enumerate()
        .map(|(share_index, assignment)| {
            let share_index = u16::try_from(share_index)
                .map_err(|_| anyhow!("multi-witness share index exceeds u16"))?;
            let share_commitment_hash = build_experimental_multi_witness_share_commitment_hash(
                &plan_stub,
                &assignment,
                share_index,
                coding,
                &certificate,
                coded_shards.as_ref(),
            )?;
            Ok(ExperimentalMultiWitnessRecoverySharePlan {
                assignment,
                share_index,
                share_count,
                recovery_threshold,
                share_commitment_hash,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let data_shard_count = recovery_threshold;
    let parity_shard_count = share_count.saturating_sub(recovery_threshold);

    Ok(ExperimentalMultiWitnessRecoveryPlan {
        payload_commitment_hash,
        recovery_committee_root_hash,
        coding_root_hash,
        recovery_window_close_ms,
        coding,
        share_count,
        recovery_threshold,
        data_shard_count,
        parity_shard_count,
        shares,
    })
}

#[cfg_attr(not(test), allow(dead_code))]
fn build_experimental_multi_witness_recovery_plan(
    header: &BlockHeader,
    transactions: &[ChainTransaction],
    witness_seed: &GuardianWitnessEpochSeed,
    witness_set: &GuardianWitnessSet,
    reassignment_depth: u8,
    share_count: u16,
    recovery_threshold: u16,
) -> Result<ExperimentalMultiWitnessRecoveryPlan> {
    if share_count < 2 {
        return Err(anyhow!(
            "experimental multi-witness recovery plan requires at least two assigned witnesses"
        ));
    }
    if recovery_threshold < 2 {
        return Err(anyhow!(
            "experimental multi-witness recovery plan requires threshold at least two"
        ));
    }
    if recovery_threshold > share_count {
        return Err(anyhow!(
            "experimental multi-witness recovery threshold cannot exceed share count"
        ));
    }

    let certificate = build_committed_surface_canonical_order_certificate(header, transactions)
        .map_err(|error| anyhow!(error))?;
    let assignments = derive_guardian_witness_assignments(
        witness_seed,
        witness_set,
        header.producer_account_id,
        header.height,
        header.view,
        reassignment_depth,
        share_count,
    )
    .map_err(|error| anyhow!(error))?;
    let payload_commitment_hash = certificate
        .bulletin_availability_certificate
        .recoverability_root;
    let coding = experimental_multi_witness_coding(share_count, recovery_threshold);
    let recovery_window_close_ms = header
        .timestamp_ms_or_legacy()
        .saturating_add(EXPERIMENTAL_RECOVERY_SCAFFOLD_WINDOW_MS);
    let assigned_manifest_hashes = assignments
        .iter()
        .map(|assignment| assignment.manifest_hash)
        .collect::<Vec<_>>();
    let recovery_committee_root_hash = hash_experimental_recovery_scaffold_component(
        b"aft::recovery::multi_witness::committee_root::v1",
        &(
            witness_seed.epoch,
            header.height,
            header.view,
            reassignment_depth,
            share_count,
            recovery_threshold,
            assigned_manifest_hashes,
        ),
    )?;
    let coding_root_hash = hash_experimental_recovery_scaffold_component(
        b"aft::recovery::multi_witness::coding_root::v1",
        &(
            payload_commitment_hash,
            certificate.ordered_transactions_root_hash,
            certificate.resulting_state_root_hash,
            recovery_committee_root_hash,
            coding,
            share_count,
            recovery_threshold,
            recovery_window_close_ms,
        ),
    )?;
    let recoverable_payload = recovery_coding_uses_recoverable_payload(coding)
        .then(|| build_recoverable_slot_payload_v3(header, transactions, &certificate))
        .transpose()?;
    let coded_shards = recoverable_payload
        .as_ref()
        .map(codec::to_bytes_canonical)
        .transpose()
        .map_err(|error| anyhow!(error))?
        .map(|payload_bytes| encode_coded_recovery_shards(coding, &payload_bytes))
        .transpose()?;
    let plan_stub = ExperimentalMultiWitnessRecoveryPlan {
        payload_commitment_hash,
        recovery_committee_root_hash,
        coding_root_hash,
        recovery_window_close_ms,
        coding,
        share_count,
        recovery_threshold,
        data_shard_count: recovery_threshold,
        parity_shard_count: share_count.saturating_sub(recovery_threshold),
        shares: Vec::new(),
    };
    let shares = assignments
        .into_iter()
        .enumerate()
        .map(|(share_index, assignment)| {
            let share_index = u16::try_from(share_index)
                .map_err(|_| anyhow!("multi-witness share index exceeds u16"))?;
            let share_commitment_hash = build_experimental_multi_witness_share_commitment_hash(
                &plan_stub,
                &assignment,
                share_index,
                coding,
                &certificate,
                coded_shards.as_ref(),
            )?;
            Ok(ExperimentalMultiWitnessRecoverySharePlan {
                assignment,
                share_index,
                share_count,
                recovery_threshold,
                share_commitment_hash,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let data_shard_count = recovery_threshold;
    let parity_shard_count = share_count.saturating_sub(recovery_threshold);

    Ok(ExperimentalMultiWitnessRecoveryPlan {
        payload_commitment_hash,
        recovery_committee_root_hash,
        coding_root_hash,
        recovery_window_close_ms,
        coding,
        share_count,
        recovery_threshold,
        data_shard_count,
        parity_shard_count,
        shares,
    })
}

fn build_experimental_multi_witness_recovery_capsule(
    height: u64,
    plan: &ExperimentalMultiWitnessRecoveryPlan,
) -> Result<RecoveryCapsule> {
    if plan.coding.is_transparent_committed_surface() {
        return Err(anyhow!(
            "multi-witness recovery capsule requires a non-trivial coded lane"
        ));
    }
    if plan.coding.is_deterministic_scaffold() {
        return Err(anyhow!(
            "multi-witness recovery capsule requires a non-trivial coded lane"
        ));
    }

    Ok(RecoveryCapsule {
        height,
        coding: plan.coding,
        recovery_committee_root_hash: plan.recovery_committee_root_hash,
        payload_commitment_hash: plan.payload_commitment_hash,
        coding_root_hash: plan.coding_root_hash,
        recovery_window_close_ms: plan.recovery_window_close_ms,
    })
}

fn build_experimental_multi_witness_recovery_binding_assignments(
    height: u64,
    plan: &ExperimentalMultiWitnessRecoveryPlan,
) -> Result<(
    RecoveryCapsule,
    Vec<ioi_types::app::GuardianWitnessRecoveryBindingAssignment>,
)> {
    let capsule = build_experimental_multi_witness_recovery_capsule(height, plan)?;
    let recovery_capsule_hash =
        canonical_recovery_capsule_hash(&capsule).map_err(|e| anyhow!(e))?;
    let assignments = plan
        .shares
        .iter()
        .map(
            |share| ioi_types::app::GuardianWitnessRecoveryBindingAssignment {
                witness_manifest_hash: share.assignment.manifest_hash,
                recovery_binding: GuardianWitnessRecoveryBinding {
                    recovery_capsule_hash,
                    share_commitment_hash: share.share_commitment_hash,
                },
            },
        )
        .collect();
    Ok((capsule, assignments))
}

fn build_assigned_recovery_share_envelopes(
    capsule: &RecoveryCapsule,
    materials: &[RecoveryShareMaterial],
) -> Result<Vec<AssignedRecoveryShareEnvelopeV1>> {
    let recovery_capsule_hash = canonical_recovery_capsule_hash(capsule).map_err(|e| anyhow!(e))?;
    Ok(materials
        .iter()
        .cloned()
        .map(|share_material| AssignedRecoveryShareEnvelopeV1 {
            recovery_capsule_hash,
            expected_share_commitment_hash: share_material.share_commitment_hash,
            share_material,
        })
        .collect())
}

fn build_invalid_canonical_close_challenge(
    header: &BlockHeader,
    proof: &SealedFinalityProof,
    challenger_account_id: AccountId,
    assignment: Option<ioi_types::app::AsymptoteObserverAssignment>,
    canonical_close: &AsymptoteObserverCanonicalClose,
    details: impl Into<String>,
) -> Result<AsymptoteObserverChallenge> {
    let mut challenge = AsymptoteObserverChallenge {
        challenge_id: [0u8; 32],
        epoch: proof.epoch,
        height: header.height,
        view: header.view,
        kind: AsymptoteObserverChallengeKind::InvalidCanonicalClose,
        challenger_account_id,
        assignment,
        observation_request: None,
        transcript: None,
        canonical_close: Some(canonical_close.clone()),
        evidence_hash: canonical_asymptote_observer_canonical_close_hash(canonical_close)
            .map_err(anyhow::Error::msg)?,
        details: details.into(),
    };
    challenge.challenge_id = ioi_crypto::algorithms::hash::sha256(
        &codec::to_bytes_canonical(&challenge).map_err(|e| anyhow!(e))?,
    )?;
    Ok(challenge)
}

fn invalid_canonical_close_details(
    header: &BlockHeader,
    proof: &SealedFinalityProof,
    assignments_hash: [u8; 32],
    transcript_commitment: &AsymptoteObserverTranscriptCommitment,
    challenge_commitment: &AsymptoteObserverChallengeCommitment,
    canonical_close: &AsymptoteObserverCanonicalClose,
    transcripts_root: [u8; 32],
    challenges_root: [u8; 32],
    transcript_count: u16,
    challenge_count: u16,
) -> Option<String> {
    if proof.finality_tier != ioi_types::app::FinalityTier::SealedFinal
        || proof.collapse_state != ioi_types::app::CollapseState::SealedFinal
    {
        return Some("canonical observer close was carried on a non-SealedFinal proof path".into());
    }
    if transcript_commitment.epoch != proof.epoch
        || transcript_commitment.height != header.height
        || transcript_commitment.view != header.view
    {
        return Some("observer transcript commitment does not bind the sealed slot".into());
    }
    if transcript_commitment.assignments_hash != assignments_hash {
        return Some(
            "observer transcript commitment assignments hash does not match the deterministic observer surface"
                .into(),
        );
    }
    if transcript_commitment.transcripts_root != transcripts_root {
        return Some(
            "observer transcript commitment does not match the canonical transcript surface".into(),
        );
    }
    if transcript_commitment.transcript_count != transcript_count {
        return Some(
            "observer transcript commitment count does not match the canonical transcript surface"
                .into(),
        );
    }
    if challenge_commitment.epoch != proof.epoch
        || challenge_commitment.height != header.height
        || challenge_commitment.view != header.view
    {
        return Some("observer challenge commitment does not bind the sealed slot".into());
    }
    if challenge_commitment.challenges_root != challenges_root {
        return Some(
            "observer challenge commitment does not match the canonical challenge surface".into(),
        );
    }
    if challenge_commitment.challenge_count != challenge_count {
        return Some(
            "observer challenge commitment count does not match the canonical challenge surface"
                .into(),
        );
    }
    if canonical_close.epoch != proof.epoch
        || canonical_close.height != header.height
        || canonical_close.view != header.view
    {
        return Some("canonical observer close does not bind the sealed slot".into());
    }
    if canonical_close.assignments_hash != assignments_hash {
        return Some(
            "canonical observer close assignments hash does not match the deterministic observer surface"
                .into(),
        );
    }
    if canonical_close.transcripts_root != transcripts_root {
        return Some(
            "canonical observer close does not match the canonical transcript surface".into(),
        );
    }
    if canonical_close.challenges_root != challenges_root {
        return Some(
            "canonical observer close does not match the canonical challenge surface".into(),
        );
    }
    if canonical_close.transcript_count != transcript_count {
        return Some(
            "canonical observer close transcript count does not match the canonical transcript surface"
                .into(),
        );
    }
    if canonical_close.challenge_count != challenge_count {
        return Some(
            "canonical observer close challenge count does not match the canonical challenge surface"
                .into(),
        );
    }
    if !proof.observer_challenges.is_empty() || challenge_count != 0 {
        return Some(
            "canonical observer close is challenge-dominated by a non-empty challenge surface"
                .into(),
        );
    }
    if canonical_close.challenge_cutoff_timestamp_ms == 0 {
        return Some("canonical observer close must carry a non-zero challenge cutoff".into());
    }
    None
}

fn decode_state_value<T: parity_scale_codec::Decode>(bytes: &[u8]) -> Result<T> {
    if let Ok(value) = codec::from_bytes_canonical::<T>(bytes) {
        return Ok(value);
    }
    let entry: StateEntry = codec::from_bytes_canonical(bytes)
        .map_err(|e| anyhow!("failed to decode StateEntry wrapper: {e}"))?;
    codec::from_bytes_canonical(&entry.value)
        .map_err(|e| anyhow!("failed to decode wrapped state value: {e}"))
}

fn decode_account_nonce(bytes: &[u8]) -> u64 {
    if let Ok(value) = decode_state_value::<u64>(bytes) {
        return value;
    }
    if bytes.len() == 8 {
        let mut raw = [0u8; 8];
        raw.copy_from_slice(bytes);
        return u64::from_le_bytes(raw);
    }
    0
}

async fn reserve_nonce_for_account(
    workload_client: &Arc<dyn WorkloadClientApi>,
    nonce_manager: &Arc<Mutex<BTreeMap<AccountId, u64>>>,
    account_id: AccountId,
) -> u64 {
    let nonce_key = [ACCOUNT_NONCE_PREFIX, account_id.as_ref()].concat();
    let state_nonce = match workload_client.query_raw_state(&nonce_key).await {
        Ok(Some(bytes)) => decode_account_nonce(&bytes),
        _ => 0,
    };

    let mut guard = nonce_manager.lock().await;
    let entry = guard.entry(account_id).or_insert(state_nonce);
    if *entry < state_nonce {
        *entry = state_nonce;
    }
    let nonce = *entry;
    *entry = entry.saturating_add(1);
    nonce
}

impl GuardianRegistryPublisher {
    async fn from_context<CS, ST, CE, V>(
        context_arc: &Arc<Mutex<MainLoopContext<CS, ST, CE, V>>>,
    ) -> Self
    where
        CS: CommitmentScheme + Clone + Send + Sync + 'static,
        ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
            + Send
            + Sync
            + 'static
            + Debug
            + Clone,
        CE: ConsensusEngine<ChainTransaction> + Send + Sync + 'static,
        V: Verifier<Commitment = CS::Commitment, Proof = CS::Proof>
            + Clone
            + Send
            + Sync
            + 'static
            + Debug,
        <CS as CommitmentScheme>::Proof: Serialize
            + for<'de> serde::Deserialize<'de>
            + Clone
            + Send
            + Sync
            + 'static
            + Debug
            + Encode
            + Decode,
        <CS as CommitmentScheme>::Commitment: Send + Sync + Debug,
    {
        let ctx = context_arc.lock().await;
        Self {
            workload_client: ctx.view_resolver.workload_client().clone(),
            tx_pool: ctx.tx_pool_ref.clone(),
            consensus_kick_tx: ctx.consensus_kick_tx.clone(),
            nonce_manager: ctx.nonce_manager.clone(),
            local_keypair: ctx.local_keypair.clone(),
            chain_id: ctx.chain_id,
        }
    }

    async fn enqueue_call(&self, method: &str, params: Vec<u8>) -> Result<()> {
        let public_key = self.local_keypair.public().encode_protobuf();
        let account_id = AccountId(account_id_from_key_material(
            SignatureSuite::ED25519,
            &public_key,
        )?);
        let nonce =
            reserve_nonce_for_account(&self.workload_client, &self.nonce_manager, account_id).await;
        let nonce_key = [ACCOUNT_NONCE_PREFIX, account_id.as_ref()].concat();
        let committed_nonce = match self.workload_client.query_raw_state(&nonce_key).await {
            Ok(Some(bytes)) => decode_account_nonce(&bytes),
            _ => 0,
        };

        let payload = SystemPayload::CallService {
            service_id: "guardian_registry".to_string(),
            method: method.to_string(),
            params,
        };
        let mut sys_tx = SystemTransaction {
            header: SignHeader {
                account_id,
                nonce,
                chain_id: self.chain_id,
                tx_version: 1,
                session_auth: None,
            },
            payload,
            signature_proof: SignatureProof::default(),
        };
        let sign_bytes = sys_tx.to_sign_bytes().map_err(|e| anyhow!(e))?;
        let signature = self.local_keypair.sign(&sign_bytes)?;
        sys_tx.signature_proof = SignatureProof {
            suite: SignatureSuite::ED25519,
            public_key,
            signature,
        };
        let tx = ChainTransaction::System(Box::new(sys_tx));
        let tx_hash = tx.hash()?;
        match self
            .tx_pool
            .add(tx, tx_hash, Some((account_id, nonce)), committed_nonce)
        {
            AddResult::Rejected(reason) => Err(anyhow!(
                "guardian_registry publication tx rejected for {method}: {reason}"
            )),
            AddResult::Known => Ok(()),
            AddResult::Ready | AddResult::Future => {
                let _ = self.consensus_kick_tx.send(());
                Ok(())
            }
        }
    }
}

fn build_canonical_observer_statement(
    proof: &SealedFinalityProof,
    guardian_checkpoint: Option<&GuardianLogCheckpoint>,
    assignment: &ioi_types::app::AsymptoteObserverAssignment,
    observer_certificate: &ioi_types::app::AsymptoteObserverCertificate,
    block_hash: [u8; 32],
) -> AsymptoteObserverStatement {
    AsymptoteObserverStatement {
        epoch: proof.epoch,
        assignment: assignment.clone(),
        block_hash,
        guardian_manifest_hash: proof.guardian_manifest_hash,
        guardian_decision_hash: proof.guardian_decision_hash,
        guardian_counter: proof.guardian_counter,
        guardian_trace_hash: proof.guardian_trace_hash,
        guardian_measurement_root: proof.guardian_measurement_root,
        guardian_checkpoint_root: guardian_checkpoint
            .map(|checkpoint| checkpoint.root_hash)
            .unwrap_or([0u8; 32]),
        verdict: observer_certificate.verdict,
        veto_kind: observer_certificate.veto_kind,
        evidence_hash: observer_certificate.evidence_hash,
    }
}

fn canonicalize_observer_sealed_finality_proof(
    header: &ioi_types::app::BlockHeader,
    policy: &AsymptotePolicy,
    block_hash: [u8; 32],
    proof: &mut SealedFinalityProof,
) -> Result<Option<CanonicalObserverPublicationArtifacts>> {
    if policy.observer_sealing_mode != AsymptoteObserverSealingMode::CanonicalChallengeV1 {
        return Ok(None);
    }
    if policy.observer_challenge_window_ms == 0 {
        return Err(anyhow!(
            "canonical observer sealing requires a non-zero challenge window"
        ));
    }
    if proof.observer_transcript_commitment.is_some()
        || proof.observer_challenge_commitment.is_some()
        || proof.observer_canonical_close.is_some()
        || proof.observer_canonical_abort.is_some()
    {
        if proof.observer_transcript_commitment.is_none()
            || proof.observer_challenge_commitment.is_none()
        {
            return Err(anyhow!(
                "canonical observer sealing proof is missing one of its observer commitments"
            ));
        }
        if proof.observer_canonical_close.is_some() == proof.observer_canonical_abort.is_some() {
            return Err(anyhow!(
                "canonical observer sealing proof must carry exactly one of canonical close or canonical abort"
            ));
        }
        if let Some(canonical_close) = proof.observer_canonical_close.clone() {
            let transcripts_root =
                canonical_asymptote_observer_transcripts_hash(&proof.observer_transcripts)
                    .map_err(|e| anyhow!(e))?;
            let transcript_count = u16::try_from(proof.observer_transcripts.len())
                .map_err(|_| anyhow!("observer transcript count exceeds u16"))?;
            let challenges_root =
                canonical_asymptote_observer_challenges_hash(&proof.observer_challenges)
                    .map_err(|e| anyhow!(e))?;
            let challenge_count = u16::try_from(proof.observer_challenges.len())
                .map_err(|_| anyhow!("observer challenge count exceeds u16"))?;
            let assignments_hash = proof
                .observer_transcript_commitment
                .as_ref()
                .expect("checked above")
                .assignments_hash;
            let transcript_commitment = proof
                .observer_transcript_commitment
                .as_ref()
                .expect("checked above");
            let challenge_commitment = proof
                .observer_challenge_commitment
                .as_ref()
                .expect("checked above");
            if let Some(details) = invalid_canonical_close_details(
                header,
                proof,
                assignments_hash,
                transcript_commitment,
                challenge_commitment,
                &canonical_close,
                transcripts_root,
                challenges_root,
                transcript_count,
                challenge_count,
            ) {
                let invalid_close_challenge = build_invalid_canonical_close_challenge(
                    header,
                    proof,
                    header.producer_account_id,
                    None,
                    &canonical_close,
                    details,
                )?;
                if !proof.observer_challenges.iter().any(|existing| {
                    existing.kind == AsymptoteObserverChallengeKind::InvalidCanonicalClose
                        && existing.evidence_hash == invalid_close_challenge.evidence_hash
                }) {
                    proof.observer_challenges.push(invalid_close_challenge);
                }
                let challenges_root =
                    canonical_asymptote_observer_challenges_hash(&proof.observer_challenges)
                        .map_err(|e| anyhow!(e))?;
                let challenge_count = u16::try_from(proof.observer_challenges.len())
                    .map_err(|_| anyhow!("observer challenge count exceeds u16"))?;
                let transcript_commitment = AsymptoteObserverTranscriptCommitment {
                    epoch: proof.epoch,
                    height: header.height,
                    view: header.view,
                    assignments_hash,
                    transcripts_root,
                    transcript_count,
                };
                let challenge_commitment = AsymptoteObserverChallengeCommitment {
                    epoch: proof.epoch,
                    height: header.height,
                    view: header.view,
                    challenges_root,
                    challenge_count,
                };
                let canonical_abort = AsymptoteObserverCanonicalAbort {
                    epoch: proof.epoch,
                    height: header.height,
                    view: header.view,
                    assignments_hash,
                    transcripts_root,
                    challenges_root,
                    transcript_count,
                    challenge_count,
                    challenge_cutoff_timestamp_ms: header
                        .timestamp_ms_or_legacy()
                        .saturating_add(policy.observer_challenge_window_ms),
                };
                proof.finality_tier = ioi_types::app::FinalityTier::BaseFinal;
                proof.collapse_state = ioi_types::app::CollapseState::Abort;
                proof.observer_transcript_commitment = Some(transcript_commitment.clone());
                proof.observer_challenge_commitment = Some(challenge_commitment.clone());
                proof.observer_canonical_close = None;
                proof.observer_canonical_abort = Some(canonical_abort.clone());
                return Ok(Some(CanonicalObserverPublicationArtifacts {
                    transcripts: proof.observer_transcripts.clone(),
                    challenges: proof.observer_challenges.clone(),
                    transcript_commitment,
                    challenge_commitment,
                    canonical_close: None,
                    canonical_abort: Some(canonical_abort),
                }));
            }
        }
        return Ok(Some(CanonicalObserverPublicationArtifacts {
            transcripts: proof.observer_transcripts.clone(),
            challenges: proof.observer_challenges.clone(),
            transcript_commitment: proof
                .observer_transcript_commitment
                .clone()
                .expect("checked above"),
            challenge_commitment: proof
                .observer_challenge_commitment
                .clone()
                .expect("checked above"),
            canonical_close: proof.observer_canonical_close.clone(),
            canonical_abort: proof.observer_canonical_abort.clone(),
        }));
    }
    if proof.observer_certificates.is_empty() {
        return Ok(None);
    }
    if !proof.veto_proofs.is_empty() {
        return Err(anyhow!(
            "canonical observer sealing cannot convert veto proofs into SealedFinal transcripts"
        ));
    }

    let assignments = proof
        .observer_certificates
        .iter()
        .map(|certificate| certificate.assignment.clone())
        .collect::<Vec<_>>();
    let assignments_hash =
        canonical_asymptote_observer_assignments_hash(&assignments).map_err(|e| anyhow!(e))?;
    if let Some(observer_close_certificate) = proof.observer_close_certificate.as_ref() {
        if observer_close_certificate.assignments_hash != assignments_hash {
            return Err(anyhow!(
                "observer close certificate assignments hash does not match observer certificates"
            ));
        }
    }

    let guardian_checkpoint = header
        .guardian_certificate
        .as_ref()
        .and_then(|certificate| certificate.log_checkpoint.as_ref());
    let transcripts = proof
        .observer_certificates
        .iter()
        .map(|observer_certificate| AsymptoteObserverTranscript {
            statement: build_canonical_observer_statement(
                proof,
                guardian_checkpoint,
                &observer_certificate.assignment,
                observer_certificate,
                block_hash,
            ),
            guardian_certificate: observer_certificate.guardian_certificate.clone(),
        })
        .collect::<Vec<_>>();
    let challenges = Vec::new();
    let transcripts_root =
        canonical_asymptote_observer_transcripts_hash(&transcripts).map_err(|e| anyhow!(e))?;
    let challenges_root =
        canonical_asymptote_observer_challenges_hash(&challenges).map_err(|e| anyhow!(e))?;
    let transcript_count = u16::try_from(transcripts.len())
        .map_err(|_| anyhow!("observer transcript count exceeds u16"))?;
    let challenge_count = u16::try_from(challenges.len())
        .map_err(|_| anyhow!("observer challenge count exceeds u16"))?;
    let challenge_cutoff_timestamp_ms = header
        .timestamp_ms_or_legacy()
        .saturating_add(policy.observer_challenge_window_ms);

    let artifacts = CanonicalObserverPublicationArtifacts {
        transcripts: transcripts.clone(),
        challenges: challenges.clone(),
        transcript_commitment: AsymptoteObserverTranscriptCommitment {
            epoch: proof.epoch,
            height: header.height,
            view: header.view,
            assignments_hash,
            transcripts_root,
            transcript_count,
        },
        challenge_commitment: AsymptoteObserverChallengeCommitment {
            epoch: proof.epoch,
            height: header.height,
            view: header.view,
            challenges_root,
            challenge_count,
        },
        canonical_close: Some(AsymptoteObserverCanonicalClose {
            epoch: proof.epoch,
            height: header.height,
            view: header.view,
            assignments_hash,
            transcripts_root,
            challenges_root,
            transcript_count,
            challenge_count,
            challenge_cutoff_timestamp_ms,
        }),
        canonical_abort: None,
    };

    proof.observer_transcripts = artifacts.transcripts.clone();
    proof.observer_challenges = artifacts.challenges.clone();
    proof.observer_transcript_commitment = Some(artifacts.transcript_commitment.clone());
    proof.observer_challenge_commitment = Some(artifacts.challenge_commitment.clone());
    proof.observer_canonical_close = artifacts.canonical_close.clone();
    proof.observer_canonical_abort = None;
    proof.observer_certificates.clear();
    proof.observer_close_certificate = None;

    Ok(Some(artifacts))
}

fn sign_sealed_finality_proof(
    proof: &mut SealedFinalityProof,
    local_keypair: &libp2p::identity::Keypair,
) -> Result<()> {
    proof.proof_signature = SignatureProof::default();
    let sign_bytes =
        canonical_sealed_finality_proof_signing_bytes(proof).map_err(anyhow::Error::msg)?;
    proof.proof_signature = SignatureProof {
        suite: SignatureSuite::ED25519,
        public_key: local_keypair.public().encode_protobuf(),
        signature: local_keypair.sign(&sign_bytes)?,
    };
    Ok(())
}

async fn publish_canonical_observer_artifacts(
    publisher: &GuardianRegistryPublisher,
    artifacts: &CanonicalObserverPublicationArtifacts,
) -> Result<()> {
    for transcript in &artifacts.transcripts {
        publisher
            .enqueue_call(
                "publish_asymptote_observer_transcript@v1",
                codec::to_bytes_canonical(transcript).map_err(|e| anyhow!(e))?,
            )
            .await?;
    }
    publisher
        .enqueue_call(
            "publish_asymptote_observer_transcript_commitment@v1",
            codec::to_bytes_canonical(&artifacts.transcript_commitment).map_err(|e| anyhow!(e))?,
        )
        .await?;
    for challenge in &artifacts.challenges {
        publisher
            .enqueue_call(
                "report_asymptote_observer_challenge@v1",
                codec::to_bytes_canonical(challenge).map_err(|e| anyhow!(e))?,
            )
            .await?;
    }
    publisher
        .enqueue_call(
            "publish_asymptote_observer_challenge_commitment@v1",
            codec::to_bytes_canonical(&artifacts.challenge_commitment).map_err(|e| anyhow!(e))?,
        )
        .await?;
    if let Some(canonical_close) = artifacts.canonical_close.as_ref() {
        publisher
            .enqueue_call(
                "publish_asymptote_observer_canonical_close@v1",
                codec::to_bytes_canonical(canonical_close).map_err(|e| anyhow!(e))?,
            )
            .await?;
    }
    if let Some(canonical_abort) = artifacts.canonical_abort.as_ref() {
        publisher
            .enqueue_call(
                "publish_asymptote_observer_canonical_abort@v1",
                codec::to_bytes_canonical(canonical_abort).map_err(|e| anyhow!(e))?,
            )
            .await?;
    }
    Ok(())
}

fn build_canonical_order_publication_bundle(
    execution_object: &CanonicalOrderExecutionObject,
) -> CanonicalOrderPublicationBundle {
    CanonicalOrderPublicationBundle {
        bulletin_commitment: execution_object.bulletin_commitment.clone(),
        bulletin_entries: execution_object.bulletin_entries.clone(),
        bulletin_availability_certificate: execution_object
            .bulletin_availability_certificate
            .clone(),
        bulletin_retrievability_profile: execution_object.bulletin_retrievability_profile.clone(),
        bulletin_shard_manifest: execution_object.bulletin_shard_manifest.clone(),
        bulletin_custody_receipt: execution_object.bulletin_custody_receipt.clone(),
        canonical_order_certificate: execution_object.canonical_order_certificate.clone(),
    }
}

fn build_canonical_order_publication_artifacts(
    header: &ioi_types::app::BlockHeader,
    transactions: &[ChainTransaction],
) -> Result<CanonicalOrderPublicationArtifacts> {
    match derive_canonical_order_execution_object(header, transactions) {
        Ok(execution_object) => Ok(CanonicalOrderPublicationArtifacts {
            bundle: Some(build_canonical_order_publication_bundle(&execution_object)),
            publication_frontier: header.publication_frontier.clone(),
            canonical_abort: None,
        }),
        Err(canonical_abort) => Ok(CanonicalOrderPublicationArtifacts {
            bundle: None,
            publication_frontier: None,
            canonical_abort: Some(canonical_abort),
        }),
    }
}

async fn publish_canonical_order_artifacts(
    publisher: &GuardianRegistryPublisher,
    artifacts: &CanonicalOrderPublicationArtifacts,
) -> Result<()> {
    if let Some(bundle) = artifacts.bundle.as_ref() {
        publisher
            .enqueue_call(
                "publish_aft_canonical_order_artifact_bundle@v1",
                codec::to_bytes_canonical(bundle).map_err(|e| anyhow!(e))?,
            )
            .await?;
    }
    if let Some(frontier) = artifacts.publication_frontier.as_ref() {
        publisher
            .enqueue_call(
                "publish_aft_publication_frontier@v1",
                codec::to_bytes_canonical(frontier).map_err(|e| anyhow!(e))?,
            )
            .await?;
    }
    if let Some(canonical_abort) = artifacts.canonical_abort.as_ref() {
        publisher
            .enqueue_call(
                "publish_aft_canonical_order_abort@v1",
                codec::to_bytes_canonical(canonical_abort).map_err(|e| anyhow!(e))?,
            )
            .await?;
    }
    Ok(())
}

async fn publish_experimental_recovery_artifacts(
    publisher: &GuardianRegistryPublisher,
    block: &Block<ChainTransaction>,
) -> Result<()> {
    let Some(guardian_certificate) = block.header.guardian_certificate.as_ref() else {
        return Ok(());
    };
    let Some(witness_certificate) = guardian_certificate
        .experimental_witness_certificate
        .as_ref()
    else {
        return Ok(());
    };
    let scaffold = build_experimental_recovery_scaffold_artifacts(
        &block.header,
        &block.transactions,
        witness_certificate.manifest_hash,
        witness_certificate.reassignment_depth,
    )?;
    let expected_binding = scaffold.recovery_binding()?;
    if witness_certificate.recovery_binding.as_ref() != Some(&expected_binding) {
        tracing::warn!(
            target: "consensus",
            height = block.header.height,
            witness_manifest_hash = %hex::encode(witness_certificate.manifest_hash),
            "Skipping recovery publication because the signed witness binding does not match the deterministic recovery scaffold."
        );
        return Ok(());
    }
    let Some(certificate) =
        derive_recovery_witness_certificate_for_header(&block.header, guardian_certificate)
            .map_err(|error| anyhow!(error))?
    else {
        return Ok(());
    };

    match publisher
        .workload_client
        .query_raw_state(&aft_recovery_capsule_key(scaffold.capsule.height))
        .await
        .map_err(|error| anyhow!("failed to query recovery capsule state: {error}"))?
    {
        Some(capsule_bytes) => {
            let existing: RecoveryCapsule = codec::from_bytes_canonical(&capsule_bytes)
                .map_err(|e| anyhow!("failed to decode recovery capsule: {e}"))?;
            if existing != scaffold.capsule {
                tracing::warn!(
                    target: "consensus",
                    height = certificate.height,
                    witness_manifest_hash = %hex::encode(certificate.witness_manifest_hash),
                    "Skipping recovery publication because a conflicting recovery capsule is already present in state."
                );
                return Ok(());
            }
        }
        None => {
            publisher
                .enqueue_call(
                    "publish_aft_recovery_capsule@v1",
                    codec::to_bytes_canonical(&scaffold.capsule).map_err(|e| anyhow!(e))?,
                )
                .await?;
        }
    }

    publisher
        .enqueue_call(
            "publish_aft_recovery_witness_certificate@v1",
            codec::to_bytes_canonical(&certificate).map_err(|e| anyhow!(e))?,
        )
        .await?;

    let receipt = build_recovery_share_receipt_for_header(&block.header, &certificate)?;
    if publisher
        .workload_client
        .query_raw_state(&aft_missing_recovery_share_key(
            receipt.height,
            &receipt.witness_manifest_hash,
        ))
        .await
        .map_err(|error| anyhow!("failed to query missing recovery share state: {error}"))?
        .is_some()
    {
        tracing::warn!(
            target: "consensus",
            height = receipt.height,
            witness_manifest_hash = %hex::encode(receipt.witness_manifest_hash),
            "Skipping recovery share receipt publication because the witness already has an objective missing-share record."
        );
        return Ok(());
    }
    match publisher
        .workload_client
        .query_raw_state(&aft_recovery_share_receipt_key(
            receipt.height,
            &receipt.witness_manifest_hash,
            &receipt.block_commitment_hash,
        ))
        .await
        .map_err(|error| anyhow!("failed to query recovery share receipt state: {error}"))?
    {
        Some(existing_receipt_bytes) => {
            let existing: RecoveryShareReceipt =
                codec::from_bytes_canonical(&existing_receipt_bytes)
                    .map_err(|e| anyhow!("failed to decode recovery share receipt: {e}"))?;
            if existing != receipt {
                tracing::warn!(
                    target: "consensus",
                    height = receipt.height,
                    witness_manifest_hash = %hex::encode(receipt.witness_manifest_hash),
                    block_commitment_hash = %hex::encode(receipt.block_commitment_hash),
                    "Skipping recovery share receipt publication because a conflicting receipt is already present in state."
                );
                return Ok(());
            }
            return Ok(());
        }
        None => {}
    }

    publisher
        .enqueue_call(
            "publish_aft_recovery_share_receipt@v1",
            codec::to_bytes_canonical(&receipt).map_err(|e| anyhow!(e))?,
        )
        .await
}

async fn publish_experimental_sealed_recovery_artifacts(
    publisher: &GuardianRegistryPublisher,
    block: &Block<ChainTransaction>,
    expected_capsule: Option<&RecoveryCapsule>,
    expected_bindings: &[ioi_types::app::GuardianWitnessRecoveryBindingAssignment],
) -> Result<()> {
    let Some(expected_capsule) = expected_capsule else {
        return Ok(());
    };
    if expected_bindings.is_empty() {
        return Ok(());
    }

    let Some(guardian_certificate) = block.header.guardian_certificate.as_ref() else {
        return Ok(());
    };
    let Some(proof) = block.header.sealed_finality_proof.as_ref() else {
        return Ok(());
    };
    if proof.witness_certificates.is_empty() {
        return Ok(());
    }
    if proof.witness_certificates.len() != expected_bindings.len() {
        tracing::warn!(
            target: "consensus",
            height = block.header.height,
            expected_witness_count = expected_bindings.len(),
            proof_witness_count = proof.witness_certificates.len(),
            "Skipping sealed recovery publication because the returned sealed proof does not carry the expected number of witness certificates."
        );
        return Ok(());
    }

    let mut expected_bindings_by_manifest = expected_bindings
        .iter()
        .cloned()
        .map(|assignment| {
            (
                assignment.witness_manifest_hash,
                assignment.recovery_binding,
            )
        })
        .collect::<BTreeMap<_, _>>();
    let mut derived_certificates = Vec::with_capacity(proof.witness_certificates.len());
    for witness_certificate in &proof.witness_certificates {
        let Some(expected_binding) =
            expected_bindings_by_manifest.remove(&witness_certificate.manifest_hash)
        else {
            tracing::warn!(
                target: "consensus",
                height = block.header.height,
                witness_manifest_hash = %hex::encode(witness_certificate.manifest_hash),
                "Skipping sealed recovery publication because the sealed proof includes an unexpected witness committee."
            );
            return Ok(());
        };
        if witness_certificate.recovery_binding.as_ref() != Some(&expected_binding) {
            tracing::warn!(
                target: "consensus",
                height = block.header.height,
                witness_manifest_hash = %hex::encode(witness_certificate.manifest_hash),
                "Skipping sealed recovery publication because the sealed proof witness binding does not match the deterministic fixed-lane recovery plan."
            );
            return Ok(());
        }

        let statement = ioi_types::app::guardian_witness_statement_for_header_with_recovery_binding(
            &block.header,
            guardian_certificate,
            witness_certificate.recovery_binding.clone(),
        );
        let Some(derived_certificate) =
            ioi_types::app::derive_recovery_witness_certificate(&statement, witness_certificate)
                .map_err(|error| anyhow!(error))?
        else {
            tracing::warn!(
                target: "consensus",
                height = block.header.height,
                witness_manifest_hash = %hex::encode(witness_certificate.manifest_hash),
                "Skipping sealed recovery publication because the witness certificate did not yield a recovery witness certificate."
            );
            return Ok(());
        };
        derived_certificates.push(derived_certificate);
    }
    if !expected_bindings_by_manifest.is_empty() {
        tracing::warn!(
            target: "consensus",
            height = block.header.height,
            missing_witness_count = expected_bindings_by_manifest.len(),
            "Skipping sealed recovery publication because one or more expected witness bindings were not carried by the sealed proof."
        );
        return Ok(());
    }

    match publisher
        .workload_client
        .query_raw_state(&aft_recovery_capsule_key(expected_capsule.height))
        .await
        .map_err(|error| anyhow!("failed to query sealed recovery capsule state: {error}"))?
    {
        Some(capsule_bytes) => {
            let existing: RecoveryCapsule = codec::from_bytes_canonical(&capsule_bytes)
                .map_err(|e| anyhow!("failed to decode sealed recovery capsule: {e}"))?;
            if existing != *expected_capsule {
                tracing::warn!(
                    target: "consensus",
                    height = block.header.height,
                    "Skipping sealed recovery publication because a conflicting recovery capsule is already present in state."
                );
                return Ok(());
            }
        }
        None => {
            publisher
                .enqueue_call(
                    "publish_aft_recovery_capsule@v1",
                    codec::to_bytes_canonical(expected_capsule).map_err(|e| anyhow!(e))?,
                )
                .await?;
        }
    }

    for certificate in derived_certificates {
        let witness_manifest_hash = certificate.witness_manifest_hash;
        let certificate_key = ioi_types::app::aft_recovery_witness_certificate_key(
            certificate.height,
            &witness_manifest_hash,
        );
        let publish_certificate = match publisher
            .workload_client
            .query_raw_state(&certificate_key)
            .await
            .map_err(|error| anyhow!("failed to query sealed recovery witness state: {error}"))?
        {
            Some(existing_certificate_bytes) => {
                let existing: ioi_types::app::RecoveryWitnessCertificate =
                    codec::from_bytes_canonical(&existing_certificate_bytes).map_err(|e| {
                        anyhow!("failed to decode sealed recovery witness certificate: {e}")
                    })?;
                if existing != certificate {
                    tracing::warn!(
                        target: "consensus",
                        height = certificate.height,
                        witness_manifest_hash = %hex::encode(witness_manifest_hash),
                        "Skipping sealed recovery publication for this witness because a conflicting recovery witness certificate is already present in state."
                    );
                    continue;
                } else {
                    false
                }
            }
            None => true,
        };
        if publish_certificate {
            publisher
                .enqueue_call(
                    "publish_aft_recovery_witness_certificate@v1",
                    codec::to_bytes_canonical(&certificate).map_err(|e| anyhow!(e))?,
                )
                .await?;
        }

        let receipt = build_recovery_share_receipt_for_header(&block.header, &certificate)?;
        if publisher
            .workload_client
            .query_raw_state(&aft_missing_recovery_share_key(
                receipt.height,
                &receipt.witness_manifest_hash,
            ))
            .await
            .map_err(|error| {
                anyhow!("failed to query sealed missing recovery share state: {error}")
            })?
            .is_some()
        {
            tracing::warn!(
                target: "consensus",
                height = receipt.height,
                witness_manifest_hash = %hex::encode(receipt.witness_manifest_hash),
                "Skipping sealed recovery share receipt publication because the witness already has an objective missing-share record."
            );
            continue;
        }
        match publisher
            .workload_client
            .query_raw_state(&aft_recovery_share_receipt_key(
                receipt.height,
                &receipt.witness_manifest_hash,
                &receipt.block_commitment_hash,
            ))
            .await
            .map_err(|error| {
                anyhow!("failed to query sealed recovery share receipt state: {error}")
            })? {
            Some(existing_receipt_bytes) => {
                let existing: RecoveryShareReceipt =
                    codec::from_bytes_canonical(&existing_receipt_bytes).map_err(|e| {
                        anyhow!("failed to decode sealed recovery share receipt: {e}")
                    })?;
                if existing != receipt {
                    tracing::warn!(
                        target: "consensus",
                        height = receipt.height,
                        witness_manifest_hash = %hex::encode(receipt.witness_manifest_hash),
                        block_commitment_hash = %hex::encode(receipt.block_commitment_hash),
                        "Skipping sealed recovery share receipt publication because a conflicting receipt is already present in state."
                    );
                }
                continue;
            }
            None => {}
        }

        publisher
            .enqueue_call(
                "publish_aft_recovery_share_receipt@v1",
                codec::to_bytes_canonical(&receipt).map_err(|e| anyhow!(e))?,
            )
            .await?;
    }

    Ok(())
}

fn select_supporting_recovery_share_materials(
    materials: &[RecoveryShareMaterial],
) -> Result<Vec<RecoveryShareMaterial>> {
    if materials.is_empty() {
        return Err(anyhow!(
            "recovered publication bundle selection requires at least one recovery share material"
        ));
    }

    let mut ordered = materials.to_vec();
    ordered.sort_unstable_by(|left, right| {
        left.witness_manifest_hash.cmp(&right.witness_manifest_hash)
    });

    let mut unique: Vec<RecoveryShareMaterial> = Vec::new();
    for material in ordered {
        if let Some(previous) = unique.last() {
            if previous.witness_manifest_hash == material.witness_manifest_hash {
                if *previous != material {
                    return Err(anyhow!(
                        "recovered publication bundle selection encountered conflicting share materials for one witness"
                    ));
                }
                continue;
            }
        }
        unique.push(material);
    }

    let reference = unique
        .first()
        .ok_or_else(|| anyhow!("recovered publication bundle selection has no materials"))?;
    for material in &unique {
        if material.height != reference.height
            || material.block_commitment_hash != reference.block_commitment_hash
            || material.coding != reference.coding
        {
            return Err(anyhow!(
                "recovered publication bundle selection requires a uniform slot, block commitment, materialization kind, and threshold"
            ));
        }
    }

    let threshold = usize::from(reference.coding.recovery_threshold);
    if unique.len() < threshold {
        return Err(anyhow!(
            "recovered publication bundle selection requires threshold-many distinct share materials"
        ));
    }

    Ok(unique.into_iter().take(threshold).collect())
}

fn build_recovered_publication_bundle(
    materials: &[RecoveryShareMaterial],
) -> Result<RecoveredPublicationBundle> {
    let supporting_materials = select_supporting_recovery_share_materials(materials)?;
    let supporting_witness_manifest_hashes =
        normalize_recovered_publication_bundle_supporting_witnesses(
            &supporting_materials
                .iter()
                .map(|material| material.witness_manifest_hash)
                .collect::<Vec<_>>(),
        )
        .map_err(|error| anyhow!(error))?;
    let (payload, publication_bundle, bulletin_close) =
        recover_canonical_order_artifact_surface_from_share_materials(&supporting_materials)
            .map_err(|error| anyhow!(error))?;
    let (payload_v5, _, _, _) =
        recover_full_canonical_order_surface_from_share_materials(&supporting_materials)
            .map_err(|error| anyhow!(error))?;
    Ok(RecoveredPublicationBundle {
        height: payload.height,
        block_commitment_hash: payload.block_commitment_hash,
        parent_block_commitment_hash: payload_v5.parent_block_hash,
        coding: supporting_materials[0].coding,
        supporting_witness_manifest_hashes,
        recoverable_slot_payload_hash: canonical_recoverable_slot_payload_v4_hash(&payload)
            .map_err(|error| anyhow!(error))?,
        recoverable_full_surface_hash: canonical_recoverable_slot_payload_v5_hash(&payload_v5)
            .map_err(|error| anyhow!(error))?,
        canonical_order_publication_bundle_hash: canonical_order_publication_bundle_hash(
            &publication_bundle,
        )
        .map_err(|error| anyhow!(error))?,
        canonical_bulletin_close_hash: canonical_bulletin_close_hash(&bulletin_close)
            .map_err(|error| anyhow!(error))?,
    })
}

#[cfg_attr(not(test), allow(dead_code))]
async fn publish_experimental_locally_held_recovery_share_materials<S>(
    publisher: &GuardianRegistryPublisher,
    signer: &S,
    block: &Block<ChainTransaction>,
    witness_seed: &GuardianWitnessEpochSeed,
    witness_set: &GuardianWitnessSet,
    reassignment_depth: u8,
    expected_bindings: &[ioi_types::app::GuardianWitnessRecoveryBindingAssignment],
) -> Result<Vec<RecoveryShareMaterial>>
where
    S: GuardianSigner + ?Sized,
{
    let mut available_materials = Vec::new();
    for expected_binding in expected_bindings {
        let Some(material) = signer
            .load_assigned_recovery_share_material(
                block.header.height,
                expected_binding.witness_manifest_hash,
                expected_binding.recovery_binding.clone(),
            )
            .await?
        else {
            continue;
        };

        let receipt = match verify_experimental_multi_witness_recovery_share_material(
            &block.header,
            &block.transactions,
            witness_seed,
            witness_set,
            reassignment_depth,
            &material,
        ) {
            Ok(receipt) => receipt,
            Err(error) => {
                tracing::warn!(
                    target: "consensus",
                    height = block.header.height,
                    witness_manifest_hash = %hex::encode(expected_binding.witness_manifest_hash),
                    error = %error,
                    "Skipping recovery share-material publication because the stored reveal does not match the deterministic committed-surface plan."
                );
                continue;
            }
        };
        if receipt.share_commitment_hash != expected_binding.recovery_binding.share_commitment_hash
        {
            tracing::warn!(
                target: "consensus",
                height = block.header.height,
                witness_manifest_hash = %hex::encode(expected_binding.witness_manifest_hash),
                "Skipping recovery share-material publication because the stored reveal does not match the signed recovery binding."
            );
            continue;
        }
        if publisher
            .workload_client
            .query_raw_state(&aft_missing_recovery_share_key(
                material.height,
                &material.witness_manifest_hash,
            ))
            .await
            .map_err(|error| anyhow!("failed to query missing recovery share state: {error}"))?
            .is_some()
        {
            tracing::warn!(
                target: "consensus",
                height = material.height,
                witness_manifest_hash = %hex::encode(material.witness_manifest_hash),
                "Skipping recovery share-material publication because the witness already has an objective missing-share record."
            );
            continue;
        }

        if let Some(existing_receipt_bytes) = publisher
            .workload_client
            .query_raw_state(&aft_recovery_share_receipt_key(
                receipt.height,
                &receipt.witness_manifest_hash,
                &receipt.block_commitment_hash,
            ))
            .await
            .map_err(|error| anyhow!("failed to query recovery share receipt state: {error}"))?
        {
            let existing: RecoveryShareReceipt =
                codec::from_bytes_canonical(&existing_receipt_bytes)
                    .map_err(|e| anyhow!("failed to decode recovery share receipt: {e}"))?;
            if existing != receipt {
                tracing::warn!(
                    target: "consensus",
                    height = receipt.height,
                    witness_manifest_hash = %hex::encode(receipt.witness_manifest_hash),
                    block_commitment_hash = %hex::encode(receipt.block_commitment_hash),
                    "Skipping recovery share-material publication because the compact receipt lane carries conflicting evidence."
                );
                continue;
            }
        }

        let material_key = aft_recovery_share_material_key(
            material.height,
            &material.witness_manifest_hash,
            &material.block_commitment_hash,
        );
        match publisher
            .workload_client
            .query_raw_state(&material_key)
            .await
            .map_err(|error| anyhow!("failed to query recovery share material state: {error}"))?
        {
            Some(existing_material_bytes) => {
                let existing: RecoveryShareMaterial =
                    codec::from_bytes_canonical(&existing_material_bytes)
                        .map_err(|e| anyhow!("failed to decode recovery share material: {e}"))?;
                if existing != material {
                    tracing::warn!(
                        target: "consensus",
                        height = material.height,
                        witness_manifest_hash = %hex::encode(material.witness_manifest_hash),
                        block_commitment_hash = %hex::encode(material.block_commitment_hash),
                        "Skipping recovery share-material publication because a conflicting reveal is already present in state."
                    );
                    continue;
                }
                available_materials.push(material);
                continue;
            }
            None => {}
        }

        publisher
            .enqueue_call(
                "publish_aft_recovery_share_material@v1",
                codec::to_bytes_canonical(&material).map_err(|e| anyhow!(e))?,
            )
            .await?;
        available_materials.push(material);
    }

    Ok(available_materials)
}

async fn publish_experimental_recovered_publication_bundle(
    publisher: &GuardianRegistryPublisher,
    materials: &[RecoveryShareMaterial],
) -> Result<Option<RecoveredPublicationBundle>> {
    let recovered = match build_recovered_publication_bundle(materials) {
        Ok(recovered) => recovered,
        Err(error) => {
            tracing::warn!(
                target: "consensus",
                error = %error,
                "Skipping recovered publication-bundle publication because the available public reveal set is not yet threshold-sufficient."
            );
            return Ok(None);
        }
    };

    let recovered_key = aft_recovered_publication_bundle_key(
        recovered.height,
        &recovered.block_commitment_hash,
        &recovered.supporting_witness_manifest_hashes,
    )
    .map_err(|error| anyhow!(error))?;
    match publisher
        .workload_client
        .query_raw_state(&recovered_key)
        .await
        .map_err(|error| anyhow!("failed to query recovered publication bundle state: {error}"))?
    {
        Some(existing_recovered_bytes) => {
            let existing: RecoveredPublicationBundle =
                codec::from_bytes_canonical(&existing_recovered_bytes)
                    .map_err(|e| anyhow!("failed to decode recovered publication bundle: {e}"))?;
            if existing != recovered {
                tracing::warn!(
                    target: "consensus",
                    height = recovered.height,
                    block_commitment_hash = %hex::encode(recovered.block_commitment_hash),
                    "Skipping recovered publication-bundle publication because a conflicting recovered object is already present in state."
                );
                return Ok(None);
            }
            Ok(Some(recovered))
        }
        None => {
            publisher
                .enqueue_call(
                    "publish_aft_recovered_publication_bundle@v1",
                    codec::to_bytes_canonical(&recovered).map_err(|e| anyhow!(e))?,
                )
                .await?;
            Ok(Some(recovered))
        }
    }
}

async fn publish_archived_recovered_history_segment(
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

fn select_unique_recovered_publication_bundle(
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

async fn load_unique_recovered_publication_bundle_for_height(
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

fn supporting_recovery_materials_for_recovered_bundle(
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

async fn publish_archived_recovered_restart_page(
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

async fn publish_archived_recovered_history_checkpoint(
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

async fn publish_archived_recovered_history_retention_receipt(
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

async fn publish_canonical_collapse_object(
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

async fn replay_committed_block_vote_once<CE>(
    consensus_engine_ref: &Arc<Mutex<CE>>,
    local_keypair: &libp2p::identity::Keypair,
    swarm_sender: &mpsc::Sender<SwarmCommand>,
    block: &Block<ChainTransaction>,
) where
    CE: ConsensusEngine<ChainTransaction> + Send + Sync + 'static,
{
    if block.header.height == 0 {
        return;
    }

    let vote_hash_vec = match block.header.hash() {
        Ok(hash) => hash,
        Err(error) => {
            tracing::debug!(
                target: "consensus",
                height = block.header.height,
                view = block.header.view,
                error = %error,
                "Skipping committed block vote replay because the block hash could not be derived."
            );
            return;
        }
    };
    let vote_hash = match to_root_hash(&vote_hash_vec) {
        Ok(hash) => hash,
        Err(error) => {
            tracing::debug!(
                target: "consensus",
                height = block.header.height,
                view = block.header.view,
                error = %error,
                "Skipping committed block vote replay because the block hash root conversion failed."
            );
            return;
        }
    };

    let our_pk = local_keypair.public().encode_protobuf();
    let our_id_hash = match account_id_from_key_material(SignatureSuite::ED25519, &our_pk) {
        Ok(id) => id,
        Err(error) => {
            tracing::debug!(
                target: "consensus",
                height = block.header.height,
                view = block.header.view,
                error = %error,
                "Skipping committed block vote replay because the local account id could not be derived."
            );
            return;
        }
    };
    let vote_payload = (block.header.height, block.header.view, vote_hash);
    let vote_bytes = match codec::to_bytes_canonical(&vote_payload) {
        Ok(bytes) => bytes,
        Err(error) => {
            tracing::debug!(
                target: "consensus",
                height = block.header.height,
                view = block.header.view,
                error = %error,
                "Skipping committed block vote replay because the vote payload could not be encoded."
            );
            return;
        }
    };
    let signature = match local_keypair.sign(&vote_bytes) {
        Ok(signature) => signature,
        Err(error) => {
            tracing::debug!(
                target: "consensus",
                height = block.header.height,
                view = block.header.view,
                error = %error,
                "Skipping committed block vote replay because the vote could not be signed."
            );
            return;
        }
    };

    let vote = ConsensusVote {
        height: block.header.height,
        view: block.header.view,
        block_hash: vote_hash,
        voter: AccountId(our_id_hash),
        signature,
    };

    if let Ok(vote_blob) = codec::to_bytes_canonical(&vote) {
        let _ = swarm_sender
            .send(SwarmCommand::BroadcastVote(vote_blob))
            .await;
    }

    let mut engine = consensus_engine_ref.lock().await;
    if let Err(error) = engine.handle_vote(vote).await {
        tracing::debug!(
            target: "consensus",
            height = block.header.height,
            view = block.header.view,
            error = %error,
            "Committed block vote replay loopback was ignored."
        );
        return;
    }
    let pending_qcs = engine.take_pending_quorum_certificates();
    drop(engine);

    for qc in pending_qcs {
        if let Ok(qc_blob) = codec::to_bytes_canonical(&qc) {
            let _ = swarm_sender
                .send(SwarmCommand::BroadcastQuorumCertificate(qc_blob))
                .await;
        }
    }
}

pub(crate) fn schedule_committed_block_vote_replays<CE>(
    consensus_engine_ref: Arc<Mutex<CE>>,
    local_keypair: libp2p::identity::Keypair,
    swarm_sender: mpsc::Sender<SwarmCommand>,
    block: Block<ChainTransaction>,
) where
    CE: ConsensusEngine<ChainTransaction> + Send + Sync + 'static,
{
    for delay_ms in post_commit_vote_replay_delays_ms() {
        let consensus_engine_ref = Arc::clone(&consensus_engine_ref);
        let local_keypair = local_keypair.clone();
        let swarm_sender = swarm_sender.clone();
        let block = block.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(delay_ms)).await;
            replay_committed_block_vote_once(
                &consensus_engine_ref,
                &local_keypair,
                &swarm_sender,
                &block,
            )
            .await;
        });
    }
}

fn schedule_post_commit_rekicks(
    tx_pool: Arc<Mempool>,
    kick_tx: mpsc::UnboundedSender<()>,
    kick_scheduled: Arc<AtomicBool>,
) {
    if tx_pool.is_empty() {
        return;
    }

    for delay_ms in post_commit_rekick_delays_ms() {
        let tx_pool = Arc::clone(&tx_pool);
        let kick_tx = kick_tx.clone();
        let kick_scheduled = Arc::clone(&kick_scheduled);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(delay_ms)).await;
            if !tx_pool.is_empty() {
                crate::standard::orchestration::schedule_consensus_kick(&kick_tx, &kick_scheduled);
            }
        });
    }
}

fn dispatch_swarm_command(sender: &tokio::sync::mpsc::Sender<SwarmCommand>, command: SwarmCommand) {
    match sender.try_send(command) {
        Ok(()) => {}
        Err(tokio::sync::mpsc::error::TrySendError::Full(command)) => {
            let sender = sender.clone();
            tokio::spawn(async move {
                let _ = sender.send(command).await;
            });
        }
        Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {}
    }
}

fn leader_accounts_for_upcoming_heights(
    local_height: u64,
    validator_ids: &[Vec<u8>],
    fanout: usize,
) -> Vec<AccountId> {
    if validator_ids.is_empty() || fanout == 0 {
        return Vec::new();
    }

    let mut leaders = Vec::new();
    let mut seen = HashSet::new();
    let validator_len = validator_ids.len() as u64;
    let steps = fanout.min(validator_ids.len());
    for offset in 1..=steps {
        let target_height = local_height.saturating_add(offset as u64).max(1);
        let leader_index = ((target_height - 1) % validator_len) as usize;
        let Some(leader_bytes) = validator_ids.get(leader_index) else {
            continue;
        };
        let Ok(leader_bytes) = <[u8; 32]>::try_from(leader_bytes.as_slice()) else {
            continue;
        };
        let account = AccountId(leader_bytes);
        if seen.insert(account) {
            leaders.push(account);
        }
    }
    leaders
}

pub async fn finalize_and_broadcast_block<CS, ST, CE, V>(
    context_arc: &Arc<Mutex<MainLoopContext<CS, ST, CE, V>>>,
    mut final_block: Block<ChainTransaction>,
    deferred_transactions: Vec<ChainTransaction>,
    signer: Arc<dyn GuardianSigner>,
    swarm_commander: &mpsc::Sender<SwarmCommand>,
    consensus_engine_ref: &Arc<Mutex<CE>>,
    tx_pool: &Arc<Mempool>,
    node_state_arc: &Arc<Mutex<NodeState>>,
) -> Result<()>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + Debug
        + Clone,
    CE: ConsensusEngine<ChainTransaction> + Send + Sync + 'static,
    V: Verifier<Commitment = CS::Commitment, Proof = CS::Proof>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug,
    <CS as CommitmentScheme>::Proof: Serialize
        + for<'de> serde::Deserialize<'de>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug
        + Encode
        + Decode,
    <CS as CommitmentScheme>::Commitment: Send + Sync + Debug,
{
    let block_height = final_block.header.height;
    let (aft_mode, consensus_type) = {
        let ctx = context_arc.lock().await;
        (ctx.config.aft_safety_mode, ctx.config.consensus_type)
    };
    if matches!(aft_mode, AftSafetyMode::Asymptote) {
        match build_committed_surface_canonical_order_certificate(
            &final_block.header,
            &final_block.transactions,
        ) {
            Ok(certificate) => {
                final_block.header.canonical_order_certificate = Some(certificate);
                let previous_publication_frontier = {
                    let ctx = context_arc.lock().await;
                    ctx.last_committed_block
                        .as_ref()
                        .and_then(|block| block.header.publication_frontier.clone())
                };
                match build_publication_frontier(
                    &final_block.header,
                    previous_publication_frontier.as_ref(),
                ) {
                    Ok(frontier) => {
                        final_block.header.publication_frontier = Some(frontier);
                    }
                    Err(error) => {
                        tracing::warn!(
                            target: "consensus",
                            height = final_block.header.height,
                            view = final_block.header.view,
                            error = %error,
                            "Failed to derive compact publication frontier; publishing canonical abort instead"
                        );
                        final_block.header.canonical_order_certificate = None;
                        final_block.header.publication_frontier = None;
                    }
                }
            }
            Err(error) => {
                tracing::warn!(
                    target: "consensus",
                    height = final_block.header.height,
                    view = final_block.header.view,
                    error = %error,
                    "Failed to derive proof-carried canonical-order certificate; publishing canonical abort instead"
                );
                final_block.header.canonical_order_certificate = None;
                final_block.header.publication_frontier = None;
            }
        }
    }
    let preimage = final_block.header.to_preimage_for_signing()?;
    let preimage_hash = ioi_crypto::algorithms::hash::sha256(&preimage)?;
    let bundle_started = Instant::now();
    let bundle =
        issue_consensus_bundle(context_arc, signer.as_ref(), &final_block, preimage_hash).await?;
    let bundle_elapsed = bundle_started.elapsed();
    if bundle_elapsed.as_millis() >= 250 {
        tracing::warn!(
            target: "consensus",
            height = block_height,
            tx_count = final_block.transactions.len(),
            elapsed_ms = bundle_elapsed.as_millis(),
            "issue_consensus_bundle() is slow"
        );
    }
    final_block.header.signature = bundle.signature;
    final_block.header.oracle_counter = bundle.counter;
    final_block.header.oracle_trace_hash = bundle.trace_hash;
    final_block.header.guardian_certificate = bundle.guardian_certificate;
    final_block.header.sealed_finality_proof = bundle.sealed_finality_proof;
    if matches!(
        aft_mode,
        AftSafetyMode::Asymptote | AftSafetyMode::ExperimentalNestedGuardian
    ) {
        let publisher = GuardianRegistryPublisher::from_context(context_arc).await;
        if matches!(aft_mode, AftSafetyMode::Asymptote) {
            let artifacts = build_canonical_order_publication_artifacts(
                &final_block.header,
                &final_block.transactions,
            )?;
            publish_canonical_order_artifacts(&publisher, &artifacts).await?;
        }
        publish_experimental_recovery_artifacts(&publisher, &final_block).await?;
    }

    {
        let ctx = context_arc.lock().await;
        let receipt_guard = ctx.receipt_map.lock().await;
        let mut status_guard = ctx.tx_status_cache.lock().await;

        for tx in &final_block.transactions {
            let tx_hash_res: Result<ioi_types::app::TxHash, _> = tx.hash();
            if let Ok(h) = tx_hash_res {
                let tx_hash_hex = receipt_guard
                    .peek(&h)
                    .cloned()
                    .unwrap_or_else(|| hex::encode(h));
                if let Some(entry) = status_guard.get_mut(&tx_hash_hex) {
                    entry.status = TxStatus::Committed;
                    entry.block_height = Some(block_height);
                } else {
                    status_guard.put(
                        tx_hash_hex,
                        crate::standard::orchestration::context::TxStatusEntry {
                            status: TxStatus::Committed,
                            error: None,
                            block_height: Some(block_height),
                        },
                    );
                }
            }
        }
    }

    let workload_client = {
        let ctx = context_arc.lock().await;
        ctx.view_resolver.workload_client().clone()
    };
    let update_header_started = Instant::now();
    workload_client
        .update_block_header(final_block.clone())
        .await
        .map_err(|error| anyhow!("failed to persist finalized block header update: {error}"))?;
    let update_header_elapsed = update_header_started.elapsed();
    if update_header_elapsed.as_millis() >= 250 {
        tracing::warn!(
            target: "consensus",
            height = final_block.header.height,
            tx_count = final_block.transactions.len(),
            elapsed_ms = update_header_elapsed.as_millis(),
            "update_block_header() is slow"
        );
    }
    let committed_collapse = require_persisted_aft_canonical_collapse_if_needed(
        consensus_type,
        workload_client.as_ref(),
        &final_block,
    )
    .await?;

    {
        let mut ctx = context_arc.lock().await;
        ctx.last_committed_block = Some(final_block.clone());
        {
            let mut chain_guard = ctx.chain_ref.lock().await;
            let status = chain_guard.status_mut();
            if block_height > status.height {
                status.total_transactions = status
                    .total_transactions
                    .saturating_add(final_block.transactions.len() as u64);
            }
            status.height = block_height;
            status.latest_timestamp = final_block.header.timestamp;
        }
        let _ = ctx.tip_sender.send(ChainTipInfo {
            height: block_height,
            timestamp: final_block.header.timestamp,
            timestamp_ms: final_block.header.timestamp_ms_or_legacy(),
            gas_used: final_block.header.gas_used,
            state_root: final_block.header.state_root.0.clone(),
            genesis_root: ctx.genesis_hash.to_vec(),
            validator_set: final_block.header.validator_set.clone(),
        });
    }

    let data = codec::to_bytes_canonical(&final_block).map_err(|e| anyhow!(e))?;
    dispatch_swarm_command(swarm_commander, SwarmCommand::PublishBlock(data));

    if matches!(aft_mode, AftSafetyMode::Asymptote) {
        let sealing_context = Arc::clone(context_arc);
        let sealing_signer = Arc::clone(&signer);
        let sealing_swarm = swarm_commander.clone();
        let sealing_block = final_block.clone();
        tokio::spawn(async move {
            if let Err(error) = seal_and_publish_block(
                &sealing_context,
                sealing_block,
                sealing_signer,
                &sealing_swarm,
            )
            .await
            {
                tracing::warn!(
                    target: "consensus",
                    event = "asymptote_sealing_failed",
                    error = %error
                );
            }
        });
    }

    if let Err(e) = crate::standard::orchestration::gossip::prune_mempool(tx_pool, &final_block) {
        tracing::error!(target: "consensus", event = "mempool_prune_fail", error=%e);
    }

    {
        let mut engine = consensus_engine_ref.lock().await;
        let accepted =
            engine.observe_committed_block(&final_block.header, committed_collapse.as_ref());
        if !accepted {
            tracing::warn!(
                target: "consensus",
                height = final_block.header.height,
                "Consensus engine ignored the committed block hint because it was not collapse-backed."
            );
        }
        engine.reset(block_height);
    }

    let mut ns = node_state_arc.lock().await;
    if *ns == NodeState::Syncing {
        *ns = NodeState::Synced;
    }

    if !final_block.transactions.is_empty() {
        tracing::info!(
            target: "consensus",
            "🧱 BLOCK #{} COMMITTED | Tx Count: {} | State Root: 0x{}",
            final_block.header.height,
            final_block.transactions.len(),
            hex::encode(&final_block.header.state_root.0[..4])
        );
    } else {
        tracing::debug!(target: "consensus", "Committed empty block #{}", final_block.header.height);
    }

    // [FIX] Self-Vote Logic for the Leader/Producer
    // The producer must vote for their own block to ensure Quorum is reached.
    if final_block.header.height > 0 {
        let (local_keypair, swarm_sender) = {
            let ctx = context_arc.lock().await;
            (ctx.local_keypair.clone(), ctx.swarm_commander.clone())
        };

        let vote_height = final_block.header.height;
        let vote_view = final_block.header.view;
        let vote_hash_vec = final_block.header.hash().unwrap_or(vec![0u8; 32]);
        let vote_hash = to_root_hash(&vote_hash_vec).unwrap_or([0u8; 32]);

        let our_pk = local_keypair.public().encode_protobuf();
        if let Ok(our_id_hash) = account_id_from_key_material(SignatureSuite::ED25519, &our_pk) {
            let our_id = AccountId(our_id_hash);

            let vote_payload = (vote_height, vote_view, vote_hash);
            if let Ok(vote_bytes) = codec::to_bytes_canonical(&vote_payload) {
                if let Ok(sig) = local_keypair.sign(&vote_bytes) {
                    let vote = ConsensusVote {
                        height: vote_height,
                        view: vote_view,
                        block_hash: vote_hash,
                        voter: our_id,
                        signature: sig,
                    };

                    if let Ok(vote_blob) = codec::to_bytes_canonical(&vote) {
                        // 1. Broadcast to network
                        dispatch_swarm_command(
                            &swarm_sender,
                            SwarmCommand::BroadcastVote(vote_blob),
                        );

                        // 2. Feed back to local engine (so we track our own contribution to the QC)
                        let mut engine = consensus_engine_ref.lock().await;
                        if let Err(e) = engine.handle_vote(vote).await {
                            tracing::warn!(target: "consensus", "Failed to handle own vote: {}", e);
                        } else {
                            let pending_qcs = engine.take_pending_quorum_certificates();
                            drop(engine);
                            for qc in pending_qcs {
                                if let Ok(qc_blob) = codec::to_bytes_canonical(&qc) {
                                    dispatch_swarm_command(
                                        &swarm_sender,
                                        SwarmCommand::BroadcastQuorumCertificate(qc_blob),
                                    );
                                }
                            }
                        }

                        tracing::info!(target: "consensus", "Self-Voted for block {} (H={} V={})", hex::encode(&vote_hash[..4]), vote_height, vote_view);
                    }
                }
            }
        }

        schedule_committed_block_vote_replays(
            Arc::clone(consensus_engine_ref),
            local_keypair,
            swarm_sender,
            final_block.clone(),
        );
    }

    {
        let relay_context = Arc::clone(context_arc);
        let relay_pool = Arc::clone(tx_pool);
        let relay_block = final_block.clone();
        let relay_deferred_transactions = deferred_transactions;
        tokio::spawn(async move {
            relay_remaining_mempool_to_upcoming_leaders(
                &relay_context,
                &relay_pool,
                &relay_block,
                relay_deferred_transactions,
            )
            .await;
        });
    }

    // A committed block usually implies the next height is immediately actionable.
    // Trigger the next consensus tick instead of waiting for the coarse timer loop.
    {
        let (kick_tx, kick_scheduled) = {
            let ctx = context_arc.lock().await;
            (
                ctx.consensus_kick_tx.clone(),
                ctx.consensus_kick_scheduled.clone(),
            )
        };
        let _ = kick_tx.send(());
        schedule_post_commit_rekicks(Arc::clone(tx_pool), kick_tx, kick_scheduled);
    }

    Ok(())
}

async fn relay_remaining_mempool_to_upcoming_leaders<CS, ST, CE, V>(
    context_arc: &Arc<Mutex<MainLoopContext<CS, ST, CE, V>>>,
    tx_pool: &Arc<Mempool>,
    committed_block: &Block<ChainTransaction>,
    deferred_transactions: Vec<ChainTransaction>,
) where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + Debug
        + Clone,
    CE: ConsensusEngine<ChainTransaction> + Send + Sync + 'static,
    V: Verifier<Commitment = CS::Commitment, Proof = CS::Proof>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug,
    <CS as CommitmentScheme>::Proof: Serialize
        + for<'de> serde::Deserialize<'de>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug
        + Encode
        + Decode,
    <CS as CommitmentScheme>::Commitment: Send + Sync + Debug,
{
    let relay_limit = post_commit_relay_limit();
    if relay_limit == 0 {
        return;
    }
    let mut pending = if deferred_transactions.is_empty() {
        tx_pool.select_transactions(relay_limit)
    } else {
        deferred_transactions
    };
    if pending.len() > relay_limit {
        pending.truncate(relay_limit);
    }
    if pending.is_empty() {
        return;
    }

    let (local_account_id, leader_peer_targets, leader_peers, swarm_commander) = {
        let ctx = context_arc.lock().await;
        let local_account_id = AccountId(
            account_id_from_key_material(
                SignatureSuite::ED25519,
                &ctx.local_keypair.public().encode_protobuf(),
            )
            .unwrap_or_default(),
        );
        let leader_accounts = leader_accounts_for_upcoming_heights(
            committed_block.header.height,
            &committed_block.header.validator_set,
            post_commit_leader_fanout(),
        );
        let leader_peer_targets = leader_accounts
            .iter()
            .filter(|account_id| **account_id != local_account_id)
            .count();
        let leader_peers = {
            let peers = ctx.peer_accounts_ref.lock().await;
            leader_accounts
                .into_iter()
                .filter(|account_id| *account_id != local_account_id)
                .filter_map(|leader_account_id| {
                    peers.iter().find_map(|(peer_id, account_id)| {
                        (*account_id == leader_account_id).then_some(*peer_id)
                    })
                })
                .collect::<Vec<_>>()
        };
        (
            local_account_id,
            leader_peer_targets,
            leader_peers,
            ctx.swarm_commander.clone(),
        )
    };
    tracing::debug!(
        target: "consensus",
        height = committed_block.header.height,
        local = %hex::encode(&local_account_id.0[..4]),
        remaining = pending.len(),
        next_leaders = leader_peers.len(),
        "Relaying remaining mempool transactions to upcoming leaders after local commit."
    );

    let direct_relay_limit = post_commit_direct_relay_limit();
    for (idx, tx) in pending.into_iter().enumerate() {
        if let Ok(data) = codec::to_bytes_canonical(&tx) {
            dispatch_swarm_command(
                &swarm_commander,
                SwarmCommand::PublishTransaction(data.clone()),
            );
            if idx < direct_relay_limit {
                for peer in &leader_peers {
                    dispatch_swarm_command(
                        &swarm_commander,
                        SwarmCommand::RelayTransactionToPeer {
                            peer: *peer,
                            data: data.clone(),
                        },
                    );
                }
            }
        }
    }
}

async fn issue_consensus_bundle<CS, ST, CE, V>(
    context_arc: &Arc<Mutex<MainLoopContext<CS, ST, CE, V>>>,
    signer: &dyn GuardianSigner,
    final_block: &Block<ChainTransaction>,
    preimage_hash: [u8; 32],
) -> Result<SignatureBundle>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + Debug
        + Clone,
    CE: ConsensusEngine<ChainTransaction> + Send + Sync + 'static,
    V: Verifier<Commitment = CS::Commitment, Proof = CS::Proof>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug,
    <CS as CommitmentScheme>::Proof: Serialize
        + for<'de> serde::Deserialize<'de>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug
        + Encode
        + Decode,
    <CS as CommitmentScheme>::Commitment: Send + Sync + Debug,
{
    let (mode, view_resolver, last_committed_block) = {
        let ctx = context_arc.lock().await;
        (
            ctx.config.aft_safety_mode,
            ctx.view_resolver.clone(),
            ctx.last_committed_block.clone(),
        )
    };

    if !matches!(
        mode,
        AftSafetyMode::ExperimentalNestedGuardian | AftSafetyMode::Asymptote
    ) {
        return signer
            .sign_consensus_payload(
                preimage_hash,
                final_block.header.height,
                final_block.header.view,
                None,
                None,
            )
            .await;
    }

    if matches!(mode, AftSafetyMode::Asymptote) {
        return signer
            .sign_consensus_payload(
                preimage_hash,
                final_block.header.height,
                final_block.header.view,
                None,
                None,
            )
            .await;
    }

    let parent_ref =
        resolve_parent_state_ref(&last_committed_block, view_resolver.as_ref()).await?;
    let parent_view = view_resolver.resolve_anchored(&parent_ref).await?;
    let current_epoch = match parent_view.get(CURRENT_EPOCH_KEY).await? {
        Some(bytes) => codec::from_bytes_canonical::<u64>(&bytes)
            .map_err(|e| anyhow!("failed to decode current epoch: {e}"))?,
        None => 1,
    };
    let witness_set: GuardianWitnessSet = codec::from_bytes_canonical(
        &parent_view
            .get(&guardian_registry_witness_set_key(current_epoch))
            .await?
            .ok_or_else(|| anyhow!("active witness set missing for epoch {}", current_epoch))?,
    )
    .map_err(|e| anyhow!("failed to decode witness set: {e}"))?;
    let witness_seed: GuardianWitnessEpochSeed = codec::from_bytes_canonical(
        &parent_view
            .get(&guardian_registry_witness_seed_key(current_epoch))
            .await?
            .ok_or_else(|| anyhow!("witness seed missing for epoch {}", current_epoch))?,
    )
    .map_err(|e| anyhow!("failed to decode witness seed: {e}"))?;

    let mut last_error: Option<anyhow::Error> = None;
    for reassignment_depth in 0..=witness_seed.max_reassignment_depth {
        let assignment = derive_guardian_witness_assignment(
            &witness_seed,
            &witness_set,
            final_block.header.producer_account_id,
            final_block.header.height,
            final_block.header.view,
            reassignment_depth,
        )
        .map_err(|e| anyhow!(e))?;
        let recovery_scaffold = build_experimental_recovery_scaffold_artifacts(
            &final_block.header,
            &final_block.transactions,
            assignment.manifest_hash,
            reassignment_depth,
        )?;
        match signer
            .sign_consensus_payload(
                preimage_hash,
                final_block.header.height,
                final_block.header.view,
                Some((assignment.manifest_hash, reassignment_depth)),
                Some(recovery_scaffold.recovery_binding()?),
            )
            .await
        {
            Ok(bundle) => {
                if reassignment_depth > 0 {
                    tracing::warn!(
                        target: "consensus",
                        event = "witness_reassigned",
                        height = final_block.header.height,
                        view = final_block.header.view,
                        reassignment_depth,
                        epoch = current_epoch,
                        "Witness stratum assignment succeeded after reassignment"
                    );
                }
                return Ok(bundle);
            }
            Err(error) => {
                let evidence = build_witness_omission_evidence(
                    &assignment,
                    final_block.header.producer_account_id,
                    &error.to_string(),
                )?;
                if let Err(report_error) = signer.report_witness_fault(&evidence).await {
                    tracing::warn!(
                        target: "consensus",
                        event = "witness_fault_report_failed",
                        error = %report_error
                    );
                }
                tracing::warn!(
                    target: "consensus",
                    event = "witness_assignment_failed",
                    height = final_block.header.height,
                    view = final_block.header.view,
                    reassignment_depth,
                    manifest_hash = %hex::encode(assignment.manifest_hash),
                    error = %error
                );
                last_error = Some(error);
            }
        }
    }

    Err(last_error.unwrap_or_else(|| anyhow!("witness stratum assignment failed")))
}

async fn seal_and_publish_block<CS, ST, CE, V>(
    context_arc: &Arc<Mutex<MainLoopContext<CS, ST, CE, V>>>,
    mut sealed_block: Block<ChainTransaction>,
    signer: Arc<dyn GuardianSigner>,
    swarm_commander: &mpsc::Sender<SwarmCommand>,
) -> Result<()>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + Debug
        + Clone,
    CE: ConsensusEngine<ChainTransaction> + Send + Sync + 'static,
    V: Verifier<Commitment = CS::Commitment, Proof = CS::Proof>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug,
    <CS as CommitmentScheme>::Proof: Serialize
        + for<'de> serde::Deserialize<'de>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug
        + Encode
        + Decode,
    <CS as CommitmentScheme>::Commitment: Send + Sync + Debug,
{
    let view_resolver = { context_arc.lock().await.view_resolver.clone() };
    let parent_ref = StateRef {
        height: sealed_block.header.height.saturating_sub(1),
        state_root: sealed_block.header.parent_state_root.as_ref().to_vec(),
        block_hash: sealed_block.header.parent_hash,
    };
    let parent_view = view_resolver.resolve_anchored(&parent_ref).await?;
    let current_epoch = match parent_view.get(CURRENT_EPOCH_KEY).await? {
        Some(bytes) => codec::from_bytes_canonical::<u64>(&bytes)
            .map_err(|e| anyhow!("failed to decode current epoch: {e}"))?,
        None => 1,
    };
    let policy: AsymptotePolicy = codec::from_bytes_canonical(
        &parent_view
            .get(&guardian_registry_asymptote_policy_key(current_epoch))
            .await?
            .ok_or_else(|| anyhow!("asymptote policy missing for epoch {}", current_epoch))?,
    )
    .map_err(|e| anyhow!("failed to decode asymptote policy: {e}"))?;
    let witness_seed: GuardianWitnessEpochSeed = codec::from_bytes_canonical(
        &parent_view
            .get(&guardian_registry_witness_seed_key(current_epoch))
            .await?
            .ok_or_else(|| anyhow!("witness seed missing for epoch {}", current_epoch))?,
    )
    .map_err(|e| anyhow!("failed to decode witness seed: {e}"))?;
    let observer_mode = policy.observer_rounds > 0 && policy.observer_committee_size > 0;
    let observer_plan = if observer_mode {
        let validator_set_bytes = parent_view
            .get(VALIDATOR_SET_KEY)
            .await?
            .ok_or_else(|| anyhow!("active validator set missing for asymptote observer mode"))?;
        let validator_sets = read_validator_sets(&validator_set_bytes)
            .map_err(|e| anyhow!("failed to decode validator set: {e}"))?;
        let active_set = effective_set_for_height(&validator_sets, sealed_block.header.height);
        let mut observer_manifests = BTreeMap::new();
        for validator in &active_set.validators {
            if validator.account_id == sealed_block.header.producer_account_id {
                continue;
            }
            let manifest_hash_bytes = parent_view
                .get(&guardian_registry_committee_account_key(
                    &validator.account_id,
                ))
                .await?
                .ok_or_else(|| {
                    anyhow!(
                        "observer guardian manifest index missing for {}",
                        hex::encode(validator.account_id)
                    )
                })?;
            let manifest_hash: [u8; 32] = manifest_hash_bytes
                .as_slice()
                .try_into()
                .map_err(|_| anyhow!("observer manifest hash must be 32 bytes"))?;
            let manifest: GuardianCommitteeManifest = codec::from_bytes_canonical(
                &parent_view
                    .get(&guardian_registry_committee_key(&manifest_hash))
                    .await?
                    .ok_or_else(|| {
                        anyhow!(
                            "observer guardian manifest missing for hash {}",
                            hex::encode(manifest_hash)
                        )
                    })?,
            )
            .map_err(|e| anyhow!("failed to decode observer guardian manifest: {e}"))?;
            observer_manifests.insert(validator.account_id, manifest);
        }
        derive_asymptote_observer_plan_entries(
            &witness_seed,
            active_set,
            &observer_manifests,
            sealed_block.header.producer_account_id,
            sealed_block.header.height,
            sealed_block.header.view,
            policy.observer_rounds,
            policy.observer_committee_size,
            &policy.observer_correlation_budget,
        )
        .map_err(|e| anyhow!(e))?
    } else {
        Vec::new()
    };
    let (
        witness_manifest_hashes,
        witness_recovery_bindings,
        witness_recovery_share_envelopes,
        sealed_recovery_capsule,
    ) = if observer_plan.is_empty() {
        let witness_set: GuardianWitnessSet = codec::from_bytes_canonical(
            &parent_view
                .get(&guardian_registry_witness_set_key(current_epoch))
                .await?
                .ok_or_else(|| anyhow!("active witness set missing for epoch {}", current_epoch))?,
        )
        .map_err(|e| anyhow!("failed to decode witness set: {e}"))?;
        let mut witness_manifests = Vec::with_capacity(witness_set.manifest_hashes.len());
        for manifest_hash in &witness_set.manifest_hashes {
            let manifest: GuardianWitnessCommitteeManifest = codec::from_bytes_canonical(
                &parent_view
                    .get(&guardian_registry_witness_key(manifest_hash))
                    .await?
                    .ok_or_else(|| {
                        anyhow!(
                            "active witness manifest missing for hash {}",
                            hex::encode(manifest_hash)
                        )
                    })?,
            )
            .map_err(|e| anyhow!("failed to decode witness manifest: {e}"))?;
            witness_manifests.push(manifest);
        }
        let witness_assignments = derive_guardian_witness_assignments_for_strata(
            &witness_seed,
            &witness_set,
            &witness_manifests,
            sealed_block.header.producer_account_id,
            sealed_block.header.height,
            sealed_block.header.view,
            0,
            &policy.required_witness_strata,
        )
        .map_err(|e| anyhow!(e))?;
        let witness_manifest_hashes = witness_assignments
            .iter()
            .map(|assignment| assignment.manifest_hash)
            .collect::<Vec<_>>();
        let witness_recovery_bindings = if let Some(recovery_threshold) =
            experimental_multi_witness_parity_threshold_for_len(witness_assignments.len())
        {
            let plan = build_experimental_multi_witness_recovery_plan_from_assignments(
                &sealed_block.header,
                &sealed_block.transactions,
                witness_seed.epoch,
                witness_assignments,
                0,
                recovery_threshold,
            )?;
            let (capsule, binding_assignments) =
                build_experimental_multi_witness_recovery_binding_assignments(
                    sealed_block.header.height,
                    &plan,
                )?;
            let share_envelopes = build_assigned_recovery_share_envelopes(
                &capsule,
                &materialize_experimental_multi_witness_recovery_share_materials_from_plan(
                    &sealed_block.header,
                    &sealed_block.transactions,
                    &plan,
                )?,
            )?;
            (binding_assignments, share_envelopes, Some(capsule))
        } else {
            (Vec::new(), Vec::new(), None)
        };
        (
            witness_manifest_hashes,
            witness_recovery_bindings.0,
            witness_recovery_bindings.1,
            witness_recovery_bindings.2,
        )
    } else {
        (Vec::new(), Vec::new(), Vec::new(), None)
    };
    let sealed_recovery_bindings = witness_recovery_bindings.clone();
    let preimage_hash =
        ioi_crypto::algorithms::hash::sha256(&sealed_block.header.to_preimage_for_signing()?)?;
    let mut sealed_finality_proof = signer
        .seal_consensus_payload(
            preimage_hash,
            sealed_block.header.height,
            sealed_block.header.view,
            witness_manifest_hashes,
            witness_recovery_bindings,
            witness_recovery_share_envelopes,
            observer_plan,
            policy.clone(),
        )
        .await?;
    let canonical_observer_artifacts = canonicalize_observer_sealed_finality_proof(
        &sealed_block.header,
        &policy,
        preimage_hash,
        &mut sealed_finality_proof,
    )?;
    let publisher = GuardianRegistryPublisher::from_context(context_arc).await;
    if let Some(artifacts) = canonical_observer_artifacts.as_ref() {
        publish_canonical_observer_artifacts(&publisher, artifacts).await?;
    }
    let local_keypair = { context_arc.lock().await.local_keypair.clone() };
    sign_sealed_finality_proof(&mut sealed_finality_proof, &local_keypair)?;

    sealed_block.header.sealed_finality_proof = Some(sealed_finality_proof);
    view_resolver
        .workload_client()
        .update_block_header(sealed_block.clone())
        .await?;
    publish_experimental_sealed_recovery_artifacts(
        &publisher,
        &sealed_block,
        sealed_recovery_capsule.as_ref(),
        &sealed_recovery_bindings,
    )
    .await?;
    let published_recovery_materials = if sealed_recovery_bindings.is_empty() {
        Vec::new()
    } else {
        let recovery_witness_set: GuardianWitnessSet = codec::from_bytes_canonical(
            &parent_view
                .get(&guardian_registry_witness_set_key(current_epoch))
                .await?
                .ok_or_else(|| anyhow!("active witness set missing for epoch {}", current_epoch))?,
        )
        .map_err(|e| anyhow!("failed to decode witness set: {e}"))?;
        publish_experimental_locally_held_recovery_share_materials(
            &publisher,
            signer.as_ref(),
            &sealed_block,
            &witness_seed,
            &recovery_witness_set,
            0,
            &sealed_recovery_bindings,
        )
        .await?
    };
    let published_recovered = publish_experimental_recovered_publication_bundle(
        &publisher,
        &published_recovery_materials,
    )
    .await?;
    let archived_profile = if published_recovered.is_some() {
        Some(ensure_archived_recovered_history_profile(&publisher).await?)
    } else {
        None
    };
    let published_archived_segment = if let (Some(recovered), Some((profile, activation))) =
        (published_recovered.as_ref(), archived_profile.as_ref())
    {
        publish_archived_recovered_history_segment(&publisher, recovered, profile, activation)
            .await?
    } else {
        None
    };
    let mut canonical_collapse_object = derive_expected_aft_canonical_collapse_for_block(
        view_resolver.workload_client().as_ref(),
        &sealed_block,
    )
    .await?
    .ok_or_else(|| {
        anyhow!("failed to derive canonical collapse object for sealed block publication")
    })?;
    let mut canonical_archived_anchor = None;
    if let (Some(recovered), Some(segment)) = (
        published_recovered.as_ref(),
        published_archived_segment.as_ref(),
    ) {
        let published_archived_page = publish_archived_recovered_restart_page(
            &publisher,
            segment,
            &canonical_collapse_object,
            recovered,
            &published_recovery_materials,
        )
        .await?;
        if let Some(page) = published_archived_page.as_ref() {
            if let Some(checkpoint) =
                publish_archived_recovered_history_checkpoint(&publisher, segment, page).await?
            {
                let mut published_receipt = None;
                if let Some((profile, _)) = archived_profile.as_ref() {
                    published_receipt = publish_archived_recovered_history_retention_receipt(
                        &publisher,
                        &checkpoint,
                        profile,
                    )
                    .await?;
                }
                canonical_archived_anchor = resolve_archived_recovered_history_anchor_hashes(
                    &publisher,
                    Some(&checkpoint),
                    published_receipt.as_ref(),
                )
                .await?;
            }
        }
    }
    if canonical_archived_anchor.is_none() {
        canonical_archived_anchor =
            resolve_archived_recovered_history_anchor_hashes(&publisher, None, None).await?;
    }
    if let Some((checkpoint_hash, activation_hash, receipt_hash)) = canonical_archived_anchor {
        set_canonical_collapse_archived_recovered_history_anchor(
            &mut canonical_collapse_object,
            checkpoint_hash,
            activation_hash,
            receipt_hash,
        )
        .map_err(|error| anyhow!(error))?;
    }
    publish_canonical_collapse_object(&publisher, &canonical_collapse_object).await?;
    let data = codec::to_bytes_canonical(&sealed_block).map_err(|e| anyhow!(e))?;
    let _ = swarm_commander.send(SwarmCommand::PublishBlock(data)).await;
    let rebroadcast_block = sealed_block.clone();
    let rebroadcast_sender = swarm_commander.clone();
    tokio::spawn(async move {
        for delay in [
            Duration::from_millis(300),
            Duration::from_millis(1200),
            Duration::from_secs(3),
            Duration::from_secs(6),
        ] {
            tokio::time::sleep(delay).await;
            let Ok(bytes) = codec::to_bytes_canonical(&rebroadcast_block) else {
                return;
            };
            let _ = rebroadcast_sender
                .send(SwarmCommand::PublishBlock(bytes))
                .await;
        }
    });
    tracing::info!(
        target: "consensus",
        event = "asymptote_sealed_block_published",
        height = sealed_block.header.height,
        view = sealed_block.header.view
    );
    Ok(())
}

fn build_witness_omission_evidence(
    assignment: &ioi_types::app::GuardianWitnessAssignment,
    producer_account_id: AccountId,
    details: &str,
) -> Result<GuardianWitnessFaultEvidence> {
    let evidence_body = codec::to_bytes_canonical(&(
        assignment.epoch,
        producer_account_id,
        assignment.height,
        assignment.view,
        assignment.manifest_hash,
        details,
    ))
    .map_err(|e| anyhow!(e.to_string()))?;
    let evidence_id = ioi_crypto::algorithms::hash::sha256(&evidence_body)?;
    Ok(GuardianWitnessFaultEvidence {
        evidence_id,
        kind: GuardianWitnessFaultKind::Omission,
        epoch: assignment.epoch,
        producer_account_id,
        height: assignment.height,
        view: assignment.view,
        expected_manifest_hash: assignment.manifest_hash,
        observed_manifest_hash: [0u8; 32],
        checkpoint_root: [0u8; 32],
        witness_certificate: None,
        details: details.to_string(),
    })
}

async fn resolve_parent_state_ref<V>(
    last_committed_block: &Option<Block<ChainTransaction>>,
    view_resolver: &dyn ioi_api::chain::ViewResolver<Verifier = V>,
) -> Result<StateRef>
where
    V: Verifier,
{
    if let Some(last) = last_committed_block.as_ref() {
        return Ok(StateRef {
            height: last.header.height,
            state_root: last.header.state_root.as_ref().to_vec(),
            block_hash: to_root_hash(last.header.hash()?)?,
        });
    }

    let genesis_root = view_resolver.genesis_root().await?;
    Ok(StateRef {
        height: 0,
        state_root: genesis_root.clone(),
        block_hash: to_root_hash(&genesis_root)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use ioi_api::app::ChainStatus;
    use ioi_api::chain::QueryStateResponse;
    use ioi_types::app::{
        build_archived_recovered_history_profile_activation, write_validator_sets,
        ArchivedRecoveredHistoryProfileActivation, ChainId, GuardianQuorumCertificate,
        GuardianWitnessCertificate, QuorumCertificate, RecoveredCanonicalHeaderEntry,
        RecoveredCertifiedHeaderEntry, RecoveredRestartBlockHeaderEntry, RecoveryCodingDescriptor,
        RecoveryCodingFamily, StateAnchor, StateRoot, ValidatorSetV1, ValidatorSetsV1, ValidatorV1,
    };
    use ioi_types::error::ChainError;
    use std::any::Any;

    #[derive(Debug, Default)]
    struct TestWorkloadClient;

    #[async_trait]
    impl WorkloadClientApi for TestWorkloadClient {
        async fn process_block(
            &self,
            _block: Block<ChainTransaction>,
        ) -> std::result::Result<(Block<ChainTransaction>, Vec<Vec<u8>>), ChainError> {
            Err(ChainError::ExecutionClient(
                "unused in finalize unit tests".to_string(),
            ))
        }

        async fn get_blocks_range(
            &self,
            _since: u64,
            _max_blocks: u32,
            _max_bytes: u32,
        ) -> std::result::Result<Vec<Block<ChainTransaction>>, ChainError> {
            Err(ChainError::ExecutionClient(
                "unused in finalize unit tests".to_string(),
            ))
        }

        async fn get_block_by_height(
            &self,
            _height: u64,
        ) -> std::result::Result<Option<Block<ChainTransaction>>, ChainError> {
            Err(ChainError::ExecutionClient(
                "unused in finalize unit tests".to_string(),
            ))
        }

        async fn check_transactions_at(
            &self,
            _anchor: StateAnchor,
            _expected_timestamp_secs: u64,
            _txs: Vec<ChainTransaction>,
        ) -> std::result::Result<Vec<std::result::Result<(), String>>, ChainError> {
            Err(ChainError::ExecutionClient(
                "unused in finalize unit tests".to_string(),
            ))
        }

        async fn query_state_at(
            &self,
            _root: StateRoot,
            _key: &[u8],
        ) -> std::result::Result<QueryStateResponse, ChainError> {
            Err(ChainError::ExecutionClient(
                "unused in finalize unit tests".to_string(),
            ))
        }

        async fn query_raw_state(
            &self,
            _key: &[u8],
        ) -> std::result::Result<Option<Vec<u8>>, ChainError> {
            Ok(None)
        }

        async fn prefix_scan(
            &self,
            _prefix: &[u8],
        ) -> std::result::Result<Vec<(Vec<u8>, Vec<u8>)>, ChainError> {
            Err(ChainError::ExecutionClient(
                "unused in finalize unit tests".to_string(),
            ))
        }

        async fn get_staked_validators(
            &self,
        ) -> std::result::Result<BTreeMap<AccountId, u64>, ChainError> {
            Err(ChainError::ExecutionClient(
                "unused in finalize unit tests".to_string(),
            ))
        }

        async fn get_genesis_status(&self) -> std::result::Result<bool, ChainError> {
            Err(ChainError::ExecutionClient(
                "unused in finalize unit tests".to_string(),
            ))
        }

        async fn update_block_header(
            &self,
            _block: Block<ChainTransaction>,
        ) -> std::result::Result<(), ChainError> {
            Err(ChainError::ExecutionClient(
                "unused in finalize unit tests".to_string(),
            ))
        }

        async fn get_state_root(&self) -> std::result::Result<StateRoot, ChainError> {
            Err(ChainError::ExecutionClient(
                "unused in finalize unit tests".to_string(),
            ))
        }

        async fn get_status(&self) -> std::result::Result<ChainStatus, ChainError> {
            Err(ChainError::ExecutionClient(
                "unused in finalize unit tests".to_string(),
            ))
        }

        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    #[derive(Debug, Default)]
    struct StaticStateWorkloadClient {
        raw_state: BTreeMap<Vec<u8>, Vec<u8>>,
    }

    #[async_trait]
    impl WorkloadClientApi for StaticStateWorkloadClient {
        async fn process_block(
            &self,
            _block: Block<ChainTransaction>,
        ) -> std::result::Result<(Block<ChainTransaction>, Vec<Vec<u8>>), ChainError> {
            Err(ChainError::ExecutionClient(
                "unused in finalize unit tests".to_string(),
            ))
        }

        async fn get_blocks_range(
            &self,
            _since: u64,
            _max_blocks: u32,
            _max_bytes: u32,
        ) -> std::result::Result<Vec<Block<ChainTransaction>>, ChainError> {
            Err(ChainError::ExecutionClient(
                "unused in finalize unit tests".to_string(),
            ))
        }

        async fn get_block_by_height(
            &self,
            _height: u64,
        ) -> std::result::Result<Option<Block<ChainTransaction>>, ChainError> {
            Err(ChainError::ExecutionClient(
                "unused in finalize unit tests".to_string(),
            ))
        }

        async fn check_transactions_at(
            &self,
            _anchor: StateAnchor,
            _expected_timestamp_secs: u64,
            _txs: Vec<ChainTransaction>,
        ) -> std::result::Result<Vec<std::result::Result<(), String>>, ChainError> {
            Err(ChainError::ExecutionClient(
                "unused in finalize unit tests".to_string(),
            ))
        }

        async fn query_state_at(
            &self,
            _root: StateRoot,
            _key: &[u8],
        ) -> std::result::Result<QueryStateResponse, ChainError> {
            Err(ChainError::ExecutionClient(
                "unused in finalize unit tests".to_string(),
            ))
        }

        async fn query_raw_state(
            &self,
            key: &[u8],
        ) -> std::result::Result<Option<Vec<u8>>, ChainError> {
            Ok(self.raw_state.get(key).cloned())
        }

        async fn prefix_scan(
            &self,
            prefix: &[u8],
        ) -> std::result::Result<Vec<(Vec<u8>, Vec<u8>)>, ChainError> {
            Ok(self
                .raw_state
                .iter()
                .filter(|(key, _)| key.starts_with(prefix))
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect())
        }

        async fn get_staked_validators(
            &self,
        ) -> std::result::Result<BTreeMap<AccountId, u64>, ChainError> {
            Err(ChainError::ExecutionClient(
                "unused in finalize unit tests".to_string(),
            ))
        }

        async fn get_genesis_status(&self) -> std::result::Result<bool, ChainError> {
            Err(ChainError::ExecutionClient(
                "unused in finalize unit tests".to_string(),
            ))
        }

        async fn update_block_header(
            &self,
            _block: Block<ChainTransaction>,
        ) -> std::result::Result<(), ChainError> {
            Err(ChainError::ExecutionClient(
                "unused in finalize unit tests".to_string(),
            ))
        }

        async fn get_state_root(&self) -> std::result::Result<StateRoot, ChainError> {
            Err(ChainError::ExecutionClient(
                "unused in finalize unit tests".to_string(),
            ))
        }

        async fn get_status(&self) -> std::result::Result<ChainStatus, ChainError> {
            Err(ChainError::ExecutionClient(
                "unused in finalize unit tests".to_string(),
            ))
        }

        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    #[derive(Debug, Default)]
    struct MockRecoveryRevealSigner {
        materials: BTreeMap<([u8; 32], [u8; 32]), RecoveryShareMaterial>,
    }

    #[async_trait]
    impl GuardianSigner for MockRecoveryRevealSigner {
        async fn sign_consensus_payload(
            &self,
            _payload_hash: [u8; 32],
            _height: u64,
            _view: u64,
            _experimental_witness_manifest: Option<([u8; 32], u8)>,
            _experimental_recovery_binding: Option<GuardianWitnessRecoveryBinding>,
        ) -> Result<SignatureBundle> {
            Err(anyhow!("unused in recovery reveal tests"))
        }

        async fn load_assigned_recovery_share_material(
            &self,
            _height: u64,
            witness_manifest_hash: [u8; 32],
            recovery_binding: GuardianWitnessRecoveryBinding,
        ) -> Result<Option<RecoveryShareMaterial>> {
            Ok(self
                .materials
                .get(&(
                    witness_manifest_hash,
                    recovery_binding.share_commitment_hash,
                ))
                .cloned())
        }

        fn public_key(&self) -> Vec<u8> {
            Vec::new()
        }
    }

    fn sample_block_header() -> ioi_types::app::BlockHeader {
        ioi_types::app::BlockHeader {
            height: 11,
            view: 4,
            parent_hash: [1u8; 32],
            parent_state_root: StateRoot(vec![2u8; 32]),
            state_root: StateRoot(vec![3u8; 32]),
            transactions_root: vec![4u8; 32],
            timestamp: 1_700_000_000,
            timestamp_ms: 1_700_000_000_000,
            gas_used: 0,
            validator_set: vec![vec![5u8; 32]],
            producer_account_id: AccountId([6u8; 32]),
            producer_key_suite: SignatureSuite::ED25519,
            producer_pubkey_hash: [7u8; 32],
            producer_pubkey: vec![8u8; 32],
            oracle_counter: 9,
            oracle_trace_hash: [10u8; 32],
            guardian_certificate: Some(GuardianQuorumCertificate {
                manifest_hash: [11u8; 32],
                epoch: 9,
                decision_hash: [12u8; 32],
                counter: 13,
                trace_hash: [14u8; 32],
                measurement_root: [15u8; 32],
                signers_bitfield: vec![1],
                aggregated_signature: vec![2],
                log_checkpoint: Some(GuardianLogCheckpoint {
                    log_id: "guardian-log".to_string(),
                    tree_size: 7,
                    root_hash: [16u8; 32],
                    timestamp_ms: 1_700_000_000_000,
                    signature: vec![3],
                    proof: None,
                }),
                experimental_witness_certificate: None,
            }),
            sealed_finality_proof: None,
            canonical_order_certificate: None,
            timeout_certificate: None,
            parent_qc: QuorumCertificate {
                height: 10,
                view: 3,
                block_hash: [17u8; 32],
                signatures: Vec::new(),
                aggregated_signature: vec![4],
                signers_bitfield: vec![1],
            },
            previous_canonical_collapse_commitment_hash: [0u8; 32],
            canonical_collapse_extension_certificate: None,
            publication_frontier: None,
            signature: vec![5],
        }
    }

    fn sample_block_with_recovery_scaffold() -> (
        Block<ChainTransaction>,
        ExperimentalRecoveryScaffoldArtifacts,
    ) {
        let mut header = sample_block_header();
        let transactions = Vec::new();
        header.transactions_root =
            ioi_types::app::canonical_transaction_root_from_hashes(&[]).expect("transactions root");
        let scaffold =
            build_experimental_recovery_scaffold_artifacts(&header, &transactions, [0x41u8; 32], 0)
                .expect("recovery scaffold");
        header
            .guardian_certificate
            .as_mut()
            .expect("sample header must carry guardian certificate")
            .experimental_witness_certificate = Some(GuardianWitnessCertificate {
            manifest_hash: [0x41u8; 32],
            stratum_id: "stratum-a".into(),
            epoch: 9,
            statement_hash: [0x42u8; 32],
            signers_bitfield: vec![0b0000_0011],
            aggregated_signature: vec![0x43],
            reassignment_depth: 0,
            recovery_binding: Some(scaffold.recovery_binding().expect("recovery binding")),
            log_checkpoint: None,
        });
        (
            Block {
                header,
                transactions,
            },
            scaffold,
        )
    }

    fn sample_block_with_sealed_recovery_bindings() -> (
        Block<ChainTransaction>,
        RecoveryCapsule,
        Vec<ioi_types::app::GuardianWitnessRecoveryBindingAssignment>,
    ) {
        let (mut header, transactions) = sample_block_header_with_ordered_transactions(0x5a);
        let witness_seed = sample_guardian_witness_seed();
        let witness_set = sample_guardian_witness_set(vec![
            [0x91u8; 32],
            [0x92u8; 32],
            [0x93u8; 32],
            [0x94u8; 32],
        ]);
        let assignments = derive_guardian_witness_assignments(
            &witness_seed,
            &witness_set,
            header.producer_account_id,
            header.height,
            header.view,
            0,
            sample_parity_family_share_count(),
        )
        .expect("derive parity-family witness assignments");
        let plan = build_experimental_multi_witness_recovery_plan_from_assignments(
            &header,
            &transactions,
            witness_seed.epoch,
            assignments,
            0,
            sample_parity_family_recovery_threshold(),
        )
        .expect("build parity-family multi-witness recovery plan");
        let (capsule, binding_assignments) =
            build_experimental_multi_witness_recovery_binding_assignments(header.height, &plan)
                .expect("build parity-family multi-witness recovery bindings");
        let guardian_certificate = header
            .guardian_certificate
            .as_ref()
            .expect("guardian certificate")
            .clone();
        header.sealed_finality_proof = Some(SealedFinalityProof {
            epoch: witness_seed.epoch,
            finality_tier: ioi_types::app::FinalityTier::SealedFinal,
            collapse_state: ioi_types::app::CollapseState::SealedFinal,
            guardian_manifest_hash: guardian_certificate.manifest_hash,
            guardian_decision_hash: guardian_certificate.decision_hash,
            guardian_counter: guardian_certificate.counter,
            guardian_trace_hash: guardian_certificate.trace_hash,
            guardian_measurement_root: guardian_certificate.measurement_root,
            policy_hash: [0x94u8; 32],
            witness_certificates: binding_assignments
                .iter()
                .enumerate()
                .map(|(index, assignment)| GuardianWitnessCertificate {
                    manifest_hash: assignment.witness_manifest_hash,
                    stratum_id: format!("stratum-{index}"),
                    epoch: witness_seed.epoch,
                    statement_hash: [0x95u8.wrapping_add(index as u8); 32],
                    signers_bitfield: vec![0b0000_0011],
                    aggregated_signature: vec![0x97u8.wrapping_add(index as u8)],
                    reassignment_depth: 0,
                    recovery_binding: Some(assignment.recovery_binding.clone()),
                    log_checkpoint: None,
                })
                .collect(),
            observer_certificates: Vec::new(),
            observer_close_certificate: None,
            observer_transcripts: Vec::new(),
            observer_challenges: Vec::new(),
            observer_transcript_commitment: None,
            observer_challenge_commitment: None,
            observer_canonical_close: None,
            observer_canonical_abort: None,
            veto_proofs: Vec::new(),
            divergence_signals: Vec::new(),
            proof_signature: SignatureProof::default(),
        });
        (
            Block {
                header,
                transactions,
            },
            capsule,
            binding_assignments,
        )
    }

    fn sample_recovery_transactions(seed: u8) -> Vec<ChainTransaction> {
        vec![
            ChainTransaction::System(Box::new(SystemTransaction {
                header: SignHeader {
                    account_id: AccountId([seed.wrapping_add(0x10); 32]),
                    nonce: 1,
                    chain_id: ioi_types::app::ChainId(1),
                    tx_version: 1,
                    session_auth: None,
                },
                payload: SystemPayload::CallService {
                    service_id: "guardian_registry".into(),
                    method: "publish_aft_bulletin_commitment@v1".into(),
                    params: vec![seed, seed.wrapping_add(1)],
                },
                signature_proof: SignatureProof::default(),
            })),
            ChainTransaction::System(Box::new(SystemTransaction {
                header: SignHeader {
                    account_id: AccountId([seed.wrapping_add(0x11); 32]),
                    nonce: 2,
                    chain_id: ioi_types::app::ChainId(1),
                    tx_version: 1,
                    session_auth: None,
                },
                payload: SystemPayload::CallService {
                    service_id: "guardian_registry".into(),
                    method: "publish_aft_canonical_order_artifact_bundle@v1".into(),
                    params: vec![seed.wrapping_add(2), seed.wrapping_add(3)],
                },
                signature_proof: SignatureProof::default(),
            })),
        ]
    }

    fn sample_block_header_with_ordered_transactions_from_header(
        mut header: ioi_types::app::BlockHeader,
        seed: u8,
    ) -> (ioi_types::app::BlockHeader, Vec<ChainTransaction>) {
        let transactions = ioi_types::app::canonicalize_transactions_for_header(
            &header,
            &sample_recovery_transactions(seed),
        )
        .expect("canonicalized transactions");
        let transaction_hashes = transactions
            .iter()
            .map(|transaction| transaction.hash().expect("transaction hash"))
            .collect::<Vec<_>>();
        header.transactions_root =
            ioi_types::app::canonical_transaction_root_from_hashes(&transaction_hashes)
                .expect("transactions root");
        (header, transactions)
    }

    fn sample_block_header_with_ordered_transactions(
        seed: u8,
    ) -> (ioi_types::app::BlockHeader, Vec<ChainTransaction>) {
        sample_block_header_with_ordered_transactions_from_header(sample_block_header(), seed)
    }

    fn recovered_publication_frontier_header(
        payload: &RecoverableSlotPayloadV5,
    ) -> ioi_types::app::BlockHeader {
        let mut header = sample_block_header();
        header.height = payload.height;
        header.view = payload.view;
        header.parent_hash = payload.parent_block_hash;
        header.parent_state_root = StateRoot(
            payload
                .canonical_order_certificate
                .resulting_state_root_hash
                .to_vec(),
        );
        header.state_root = StateRoot(
            payload
                .canonical_order_certificate
                .resulting_state_root_hash
                .to_vec(),
        );
        header.transactions_root = payload
            .canonical_order_certificate
            .ordered_transactions_root_hash
            .to_vec();
        header.timestamp_ms = payload
            .canonical_order_certificate
            .bulletin_commitment
            .cutoff_timestamp_ms;
        header.timestamp = header.timestamp_ms / 1_000;
        header.producer_account_id = payload.producer_account_id;
        header.canonical_order_certificate = Some(payload.canonical_order_certificate.clone());
        header.publication_frontier = None;
        header
    }

    fn sample_guardian_witness_seed() -> GuardianWitnessEpochSeed {
        GuardianWitnessEpochSeed {
            epoch: 9,
            seed: [0x21u8; 32],
            checkpoint_interval_blocks: 16,
            max_reassignment_depth: 0,
        }
    }

    fn sample_guardian_witness_set(manifest_hashes: Vec<[u8; 32]>) -> GuardianWitnessSet {
        GuardianWitnessSet {
            epoch: 9,
            manifest_hashes,
            checkpoint_interval_blocks: 16,
        }
    }

    fn synthetic_recovered_publication_bundle_for_height(
        template: &RecoveredPublicationBundle,
        height: u64,
    ) -> RecoveredPublicationBundle {
        let seed = (height as u8).wrapping_mul(7).wrapping_add(0x31);
        let mut bundle = template.clone();
        bundle.height = height;
        bundle.block_commitment_hash = [seed; 32];
        bundle.parent_block_commitment_hash = [seed.wrapping_sub(1); 32];
        bundle.recoverable_slot_payload_hash = [seed.wrapping_add(1); 32];
        bundle.recoverable_full_surface_hash = [seed.wrapping_add(2); 32];
        bundle.canonical_order_publication_bundle_hash = [seed.wrapping_add(3); 32];
        bundle.canonical_bulletin_close_hash = [seed.wrapping_add(4); 32];
        bundle
    }

    fn validator_sets(validators: &[(u8, u128)]) -> ValidatorSetsV1 {
        let entries = validators
            .iter()
            .map(|(account, weight)| ValidatorV1 {
                account_id: AccountId([*account; 32]),
                weight: *weight,
                consensus_key: Default::default(),
            })
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

    fn sample_previous_canonical_collapse_object(height: u64, seed: u8) -> CanonicalCollapseObject {
        CanonicalCollapseObject {
            height,
            previous_canonical_collapse_commitment_hash: [0u8; 32],
            continuity_accumulator_hash: [0u8; 32],
            continuity_recursive_proof: Default::default(),
            archived_recovered_history_checkpoint_hash: [0u8; 32],
            archived_recovered_history_profile_activation_hash: [0u8; 32],
            archived_recovered_history_retention_receipt_hash: [0u8; 32],
            ordering: ioi_types::app::CanonicalOrderingCollapse {
                height,
                kind: ioi_types::app::CanonicalCollapseKind::Close,
                bulletin_commitment_hash: [seed; 32],
                bulletin_availability_certificate_hash: [seed.wrapping_add(1); 32],
                bulletin_retrievability_profile_hash: [0u8; 32],
                bulletin_shard_manifest_hash: [0u8; 32],
                bulletin_custody_receipt_hash: [0u8; 32],
                bulletin_close_hash: [seed.wrapping_add(2); 32],
                canonical_order_certificate_hash: [seed.wrapping_add(3); 32],
            },
            sealing: None,
            transactions_root_hash: [seed.wrapping_add(4); 32],
            resulting_state_root_hash: [seed.wrapping_add(5); 32],
        }
    }

    fn synthetic_archived_restart_page(
        segment: &ArchivedRecoveredHistorySegment,
        terminal_block_hash: [u8; 32],
    ) -> ArchivedRecoveredRestartPage {
        let mut entries = Vec::new();
        let mut previous_block_hash = [0x31u8; 32];
        let mut previous_state_root_hash = [0x41u8; 32];
        for height in segment.start_height..=segment.end_height {
            let seed = (height as u8).wrapping_mul(5).wrapping_add(0x53);
            let block_hash = if height == segment.end_height {
                terminal_block_hash
            } else {
                [seed; 32]
            };
            let certified_header = RecoveredCertifiedHeaderEntry {
                header: RecoveredCanonicalHeaderEntry {
                    height,
                    view: height + 10,
                    canonical_block_commitment_hash: block_hash,
                    parent_block_commitment_hash: previous_block_hash,
                    transactions_root_hash: [seed.wrapping_add(1); 32],
                    resulting_state_root_hash: [seed.wrapping_add(2); 32],
                    previous_canonical_collapse_commitment_hash: [seed.wrapping_add(3); 32],
                },
                certified_parent_quorum_certificate: QuorumCertificate {
                    height: height.saturating_sub(1),
                    view: height + 9,
                    block_hash: previous_block_hash,
                    ..Default::default()
                },
                certified_parent_resulting_state_root_hash: previous_state_root_hash,
            };
            entries.push(RecoveredRestartBlockHeaderEntry {
                certified_header: certified_header.clone(),
                header: BlockHeader {
                    height,
                    view: certified_header.header.view,
                    parent_hash: previous_block_hash,
                    parent_state_root: StateRoot(previous_state_root_hash.to_vec()),
                    state_root: StateRoot(
                        certified_header.header.resulting_state_root_hash.to_vec(),
                    ),
                    transactions_root: certified_header.header.transactions_root_hash.to_vec(),
                    timestamp: 1_760_000_000 + height,
                    timestamp_ms: (1_760_000_000 + height) * 1_000,
                    gas_used: 0,
                    validator_set: Vec::new(),
                    producer_account_id: AccountId([seed.wrapping_add(4); 32]),
                    producer_key_suite: SignatureSuite::ED25519,
                    producer_pubkey_hash: [seed.wrapping_add(5); 32],
                    producer_pubkey: Vec::new(),
                    oracle_counter: 0,
                    oracle_trace_hash: [0u8; 32],
                    parent_qc: certified_header.certified_parent_quorum_certificate.clone(),
                    previous_canonical_collapse_commitment_hash: certified_header
                        .header
                        .previous_canonical_collapse_commitment_hash,
                    canonical_collapse_extension_certificate: None,
                    publication_frontier: None,
                    guardian_certificate: None,
                    sealed_finality_proof: None,
                    canonical_order_certificate: None,
                    timeout_certificate: None,
                    signature: Vec::new(),
                },
            });
            previous_block_hash = block_hash;
            previous_state_root_hash = certified_header.header.resulting_state_root_hash;
        }
        build_archived_recovered_restart_page(segment, &entries)
            .expect("synthetic archived recovered restart page")
    }

    fn sample_parity_family_share_count() -> u16 {
        4
    }

    fn sample_parity_family_recovery_threshold() -> u16 {
        sample_parity_family_share_count() - 1
    }

    fn sample_gf256_2_of_4_share_count() -> u16 {
        4
    }

    fn sample_gf256_2_of_4_recovery_threshold() -> u16 {
        2
    }

    fn sample_gf256_3_of_5_share_count() -> u16 {
        5
    }

    fn sample_gf256_3_of_5_recovery_threshold() -> u16 {
        3
    }

    fn sample_gf256_3_of_7_share_count() -> u16 {
        7
    }

    fn sample_gf256_3_of_7_recovery_threshold() -> u16 {
        3
    }

    fn sample_gf256_4_of_6_share_count() -> u16 {
        6
    }

    fn sample_gf256_4_of_6_recovery_threshold() -> u16 {
        4
    }

    fn sample_gf256_4_of_7_share_count() -> u16 {
        7
    }

    fn sample_gf256_4_of_7_recovery_threshold() -> u16 {
        4
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

    fn sample_manifest_hashes(seed: u8, share_count: u16) -> Vec<[u8; 32]> {
        (0..share_count)
            .map(|offset| [seed.wrapping_add(offset as u8); 32])
            .collect()
    }

    fn collect_index_combinations(total: usize, choose: usize) -> Vec<Vec<usize>> {
        fn recurse(
            total: usize,
            choose: usize,
            next_index: usize,
            current: &mut Vec<usize>,
            all: &mut Vec<Vec<usize>>,
        ) {
            if current.len() == choose {
                all.push(current.clone());
                return;
            }
            let remaining = choose - current.len();
            for index in next_index..=total - remaining {
                current.push(index);
                recurse(total, choose, index + 1, current, all);
                current.pop();
            }
        }

        if choose == 0 {
            return vec![Vec::new()];
        }
        let mut all = Vec::new();
        let mut current = Vec::new();
        recurse(total, choose, 0, &mut current, &mut all);
        all
    }

    fn select_recovery_share_materials(
        materials: &[RecoveryShareMaterial],
        indices: &[usize],
    ) -> Vec<RecoveryShareMaterial> {
        indices
            .iter()
            .map(|index| materials[*index].clone())
            .collect()
    }

    fn assert_coded_recovery_family_subset_conformance_case(
        transaction_seed: u8,
        manifest_seed: u8,
        share_count: u16,
        recovery_threshold: u16,
    ) {
        let (header, transactions) =
            sample_block_header_with_ordered_transactions(transaction_seed);
        let certificate =
            build_committed_surface_canonical_order_certificate(&header, &transactions)
                .expect("canonical order certificate");
        let witness_seed = sample_guardian_witness_seed();
        let witness_set =
            sample_guardian_witness_set(sample_manifest_hashes(manifest_seed, share_count));
        let materials = build_experimental_multi_witness_recovery_share_materials(
            &header,
            &transactions,
            &witness_seed,
            &witness_set,
            0,
            share_count,
            recovery_threshold,
        )
        .expect("share materials");
        let expected_coding = experimental_multi_witness_coding(share_count, recovery_threshold);
        assert_eq!(materials[0].coding, expected_coding);
        assert!(expected_coding
            .family_contract()
            .expect("coded recovery-family contract")
            .supports_coded_payload_reconstruction());
        let expected_payload =
            build_recoverable_slot_payload_v3(&header, &transactions, &certificate)
                .expect("recoverable payload");
        let expected_bundle: CanonicalOrderPublicationBundle =
            codec::from_bytes_canonical(&expected_payload.canonical_order_publication_bundle_bytes)
                .expect("expected publication bundle");

        for material in &materials {
            let receipt = verify_experimental_multi_witness_recovery_share_material(
                &header,
                &transactions,
                &witness_seed,
                &witness_set,
                0,
                material,
            )
            .expect("share material should verify in conformance harness");
            assert_eq!(receipt, material.to_recovery_share_receipt());
        }

        for indices in collect_index_combinations(materials.len(), usize::from(recovery_threshold))
        {
            let subset = select_recovery_share_materials(&materials, &indices);
            let recovered = recover_recoverable_slot_payload_v3_from_share_materials(&subset)
                .unwrap_or_else(|error| {
                    panic!(
                        "threshold subset {indices:?} should reconstruct for {}-of-{}: {error}",
                        recovery_threshold, share_count
                    )
                });
            let (recovered_payload, recovered_bundle) =
                recover_canonical_order_publication_bundle_from_share_materials(&subset)
                    .unwrap_or_else(|error| {
                        panic!(
                            "threshold subset {indices:?} should recover publication bundle for {}-of-{}: {error}",
                            recovery_threshold, share_count
                        )
                    });
            assert_eq!(recovered, expected_payload);
            assert_eq!(recovered_payload, expected_payload);
            assert_eq!(recovered_bundle, expected_bundle);
        }

        for indices in collect_index_combinations(
            materials.len(),
            usize::from(recovery_threshold.saturating_sub(1)),
        ) {
            let subset = select_recovery_share_materials(&materials, &indices);
            let error = recover_recoverable_slot_payload_v3_from_share_materials(&subset)
                .expect_err("below-threshold subset should not reconstruct");
            let error_text = error.to_string();
            assert!(
                error_text.contains(&format!(
                    "requires at least {recovery_threshold} distinct share reveals"
                )),
                "unexpected below-threshold error for {}-of-{} subset {indices:?}: {error_text}",
                recovery_threshold,
                share_count
            );
        }
    }

    fn assert_coded_recovery_family_commitment_determinism_case(
        transaction_seed: u8,
        manifest_seed: u8,
        alternate_manifest_seed: u8,
        share_count: u16,
        recovery_threshold: u16,
    ) {
        let witness_seed = sample_guardian_witness_seed();
        let witness_set =
            sample_guardian_witness_set(sample_manifest_hashes(manifest_seed, share_count));
        let alternate_witness_set = sample_guardian_witness_set(sample_manifest_hashes(
            alternate_manifest_seed,
            share_count,
        ));
        let (header_a, transactions_a) =
            sample_block_header_with_ordered_transactions(transaction_seed);
        let (header_b, transactions_b) =
            sample_block_header_with_ordered_transactions(transaction_seed.wrapping_add(1));
        let materials_a = build_experimental_multi_witness_recovery_share_materials(
            &header_a,
            &transactions_a,
            &witness_seed,
            &witness_set,
            0,
            share_count,
            recovery_threshold,
        )
        .expect("share materials a");
        let materials_a_repeat = build_experimental_multi_witness_recovery_share_materials(
            &header_a,
            &transactions_a,
            &witness_seed,
            &witness_set,
            0,
            share_count,
            recovery_threshold,
        )
        .expect("share materials a repeat");
        let materials_b = build_experimental_multi_witness_recovery_share_materials(
            &header_b,
            &transactions_b,
            &witness_seed,
            &witness_set,
            0,
            share_count,
            recovery_threshold,
        )
        .expect("share materials b");
        let materials_membership = build_experimental_multi_witness_recovery_share_materials(
            &header_a,
            &transactions_a,
            &witness_seed,
            &alternate_witness_set,
            0,
            share_count,
            recovery_threshold,
        )
        .expect("share materials membership");

        let commitments_a = materials_a
            .iter()
            .map(|material| material.share_commitment_hash)
            .collect::<Vec<_>>();
        let commitments_a_repeat = materials_a_repeat
            .iter()
            .map(|material| material.share_commitment_hash)
            .collect::<Vec<_>>();
        let commitments_b = materials_b
            .iter()
            .map(|material| material.share_commitment_hash)
            .collect::<Vec<_>>();
        let commitments_membership = materials_membership
            .iter()
            .map(|material| material.share_commitment_hash)
            .collect::<Vec<_>>();

        let bytes_a = materials_a
            .iter()
            .map(|material| material.material_bytes.clone())
            .collect::<Vec<_>>();
        let bytes_a_repeat = materials_a_repeat
            .iter()
            .map(|material| material.material_bytes.clone())
            .collect::<Vec<_>>();
        let bytes_b = materials_b
            .iter()
            .map(|material| material.material_bytes.clone())
            .collect::<Vec<_>>();
        let bytes_membership = materials_membership
            .iter()
            .map(|material| material.material_bytes.clone())
            .collect::<Vec<_>>();

        assert_eq!(commitments_a, commitments_a_repeat);
        assert_eq!(bytes_a, bytes_a_repeat);
        assert_ne!(commitments_a, commitments_b);
        assert_ne!(bytes_a, bytes_b);
        assert_ne!(commitments_a, commitments_membership);
        assert_eq!(bytes_a, bytes_membership);
    }

    #[test]
    fn experimental_recovery_scaffold_changes_with_witness_manifest() {
        let mut header = sample_block_header();
        header.transactions_root =
            ioi_types::app::canonical_transaction_root_from_hashes(&[]).expect("transactions root");
        let certificate = build_committed_surface_canonical_order_certificate(&header, &[])
            .expect("canonical order certificate");
        let scaffold_a =
            build_experimental_recovery_scaffold_artifacts(&header, &[], [0x41u8; 32], 0)
                .expect("scaffold a");
        let scaffold_b =
            build_experimental_recovery_scaffold_artifacts(&header, &[], [0x42u8; 32], 0)
                .expect("scaffold b");

        assert_eq!(
            scaffold_a.capsule.payload_commitment_hash,
            certificate
                .bulletin_availability_certificate
                .recoverability_root
        );
        assert_eq!(
            scaffold_b.capsule.payload_commitment_hash,
            certificate
                .bulletin_availability_certificate
                .recoverability_root
        );
        assert_ne!(scaffold_a.capsule, scaffold_b.capsule);
        assert_ne!(
            scaffold_a.capsule.coding_root_hash,
            scaffold_b.capsule.coding_root_hash
        );
        assert_ne!(
            scaffold_a.share_commitment_hash,
            scaffold_b.share_commitment_hash
        );
        assert_eq!(
            scaffold_a.capsule.coding.family,
            RecoveryCodingFamily::DeterministicScaffoldV1
        );
        assert_eq!(scaffold_a.capsule.coding.recovery_threshold, 1);
    }

    #[test]
    fn experimental_multi_witness_recovery_plan_changes_with_membership() {
        let mut header = sample_block_header();
        header.transactions_root =
            ioi_types::app::canonical_transaction_root_from_hashes(&[]).expect("transactions root");
        let certificate = build_committed_surface_canonical_order_certificate(&header, &[])
            .expect("canonical order certificate");
        let witness_seed = sample_guardian_witness_seed();
        let plan_a = build_experimental_multi_witness_recovery_plan(
            &header,
            &[],
            &witness_seed,
            &sample_guardian_witness_set(vec![[0x31u8; 32], [0x32u8; 32], [0x33u8; 32]]),
            0,
            3,
            2,
        )
        .expect("plan a");
        let plan_b = build_experimental_multi_witness_recovery_plan(
            &header,
            &[],
            &witness_seed,
            &sample_guardian_witness_set(vec![[0x31u8; 32], [0x32u8; 32], [0x34u8; 32]]),
            0,
            3,
            2,
        )
        .expect("plan b");

        assert_eq!(
            plan_a.payload_commitment_hash,
            certificate
                .bulletin_availability_certificate
                .recoverability_root
        );
        assert_eq!(
            plan_a.payload_commitment_hash,
            plan_b.payload_commitment_hash
        );
        assert_ne!(
            plan_a.recovery_committee_root_hash,
            plan_b.recovery_committee_root_hash
        );
        assert_ne!(plan_a.coding_root_hash, plan_b.coding_root_hash);
        assert_ne!(
            plan_a
                .shares
                .iter()
                .map(|share| share.assignment.manifest_hash)
                .collect::<Vec<_>>(),
            plan_b
                .shares
                .iter()
                .map(|share| share.assignment.manifest_hash)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn experimental_multi_witness_recovery_plan_changes_with_threshold() {
        let mut header = sample_block_header();
        header.transactions_root =
            ioi_types::app::canonical_transaction_root_from_hashes(&[]).expect("transactions root");
        let certificate = build_committed_surface_canonical_order_certificate(&header, &[])
            .expect("canonical order certificate");
        let witness_seed = sample_guardian_witness_seed();
        let witness_set = sample_guardian_witness_set(vec![
            [0x41u8; 32],
            [0x42u8; 32],
            [0x43u8; 32],
            [0x44u8; 32],
        ]);
        let threshold_two = build_experimental_multi_witness_recovery_plan(
            &header,
            &[],
            &witness_seed,
            &witness_set,
            0,
            sample_gf256_2_of_4_share_count(),
            sample_gf256_2_of_4_recovery_threshold(),
        )
        .expect("threshold two plan");
        let threshold_three = build_experimental_multi_witness_recovery_plan(
            &header,
            &[],
            &witness_seed,
            &witness_set,
            0,
            sample_parity_family_share_count(),
            sample_parity_family_recovery_threshold(),
        )
        .expect("threshold three plan");

        assert_eq!(
            threshold_two.payload_commitment_hash,
            certificate
                .bulletin_availability_certificate
                .recoverability_root
        );
        assert_eq!(
            threshold_two.payload_commitment_hash,
            threshold_three.payload_commitment_hash
        );
        assert_eq!(threshold_two.share_count, threshold_three.share_count);
        assert_eq!(
            threshold_two.coding,
            gf256_recovery_coding(
                sample_gf256_2_of_4_share_count(),
                sample_gf256_2_of_4_recovery_threshold(),
            )
        );
        assert_eq!(
            threshold_three.coding,
            xor_recovery_coding(
                sample_parity_family_share_count(),
                sample_parity_family_recovery_threshold(),
            )
        );
        assert_ne!(
            threshold_two.recovery_threshold,
            threshold_three.recovery_threshold
        );
        assert_ne!(
            threshold_two.coding_root_hash,
            threshold_three.coding_root_hash
        );
        assert_ne!(
            threshold_two
                .shares
                .iter()
                .map(|share| share.share_commitment_hash)
                .collect::<Vec<_>>(),
            threshold_three
                .shares
                .iter()
                .map(|share| share.share_commitment_hash)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn experimental_multi_witness_recovery_plan_rejects_threshold_one() {
        let mut header = sample_block_header();
        header.transactions_root =
            ioi_types::app::canonical_transaction_root_from_hashes(&[]).expect("transactions root");
        let error = build_experimental_multi_witness_recovery_plan(
            &header,
            &[],
            &sample_guardian_witness_seed(),
            &sample_guardian_witness_set(vec![[0x51u8; 32], [0x52u8; 32]]),
            0,
            2,
            1,
        )
        .expect_err("threshold-one plan should be rejected");

        assert!(
            error
                .to_string()
                .contains("requires threshold at least two"),
            "unexpected error: {error:#}"
        );
    }

    #[test]
    fn experimental_multi_witness_recovery_share_material_builds_and_verifies() {
        let (header, transactions) = sample_block_header_with_ordered_transactions(0x51);
        let witness_seed = sample_guardian_witness_seed();
        let witness_set = sample_guardian_witness_set(vec![
            [0x61u8; 32],
            [0x62u8; 32],
            [0x63u8; 32],
            [0x64u8; 32],
        ]);
        let materials = build_experimental_multi_witness_recovery_share_materials(
            &header,
            &transactions,
            &witness_seed,
            &witness_set,
            0,
            sample_gf256_2_of_4_share_count(),
            sample_gf256_2_of_4_recovery_threshold(),
        )
        .expect("share materials");

        assert_eq!(
            materials.len(),
            usize::from(sample_gf256_2_of_4_share_count())
        );
        let expected_block_commitment_hash =
            canonical_block_commitment_hash(&header).expect("block commitment hash");
        for (expected_index, material) in materials.iter().enumerate() {
            assert_eq!(material.height, header.height);
            assert_eq!(
                material.block_commitment_hash,
                expected_block_commitment_hash
            );
            assert_eq!(
                material.coding,
                gf256_recovery_coding(
                    sample_gf256_2_of_4_share_count(),
                    sample_gf256_2_of_4_recovery_threshold(),
                )
            );
            assert_eq!(usize::from(material.share_index), expected_index);
            assert!(!material.material_bytes.is_empty());

            let receipt = verify_experimental_multi_witness_recovery_share_material(
                &header,
                &transactions,
                &witness_seed,
                &witness_set,
                0,
                material,
            )
            .expect("share material should verify");
            assert_eq!(receipt, material.to_recovery_share_receipt());
        }
    }

    #[test]
    fn experimental_multi_witness_recovery_share_material_builds_and_verifies_for_three_of_five_gf256(
    ) {
        let (header, transactions) = sample_block_header_with_ordered_transactions(0x5b);
        let witness_seed = sample_guardian_witness_seed();
        let witness_set = sample_guardian_witness_set(vec![
            [0x91u8; 32],
            [0x92u8; 32],
            [0x93u8; 32],
            [0x94u8; 32],
            [0x95u8; 32],
        ]);
        let materials = build_experimental_multi_witness_recovery_share_materials(
            &header,
            &transactions,
            &witness_seed,
            &witness_set,
            0,
            sample_gf256_3_of_5_share_count(),
            sample_gf256_3_of_5_recovery_threshold(),
        )
        .expect("share materials");

        assert_eq!(
            materials.len(),
            usize::from(sample_gf256_3_of_5_share_count())
        );
        let expected_block_commitment_hash =
            canonical_block_commitment_hash(&header).expect("block commitment hash");
        for (expected_index, material) in materials.iter().enumerate() {
            assert_eq!(material.height, header.height);
            assert_eq!(
                material.block_commitment_hash,
                expected_block_commitment_hash
            );
            assert_eq!(
                material.coding,
                gf256_recovery_coding(
                    sample_gf256_3_of_5_share_count(),
                    sample_gf256_3_of_5_recovery_threshold(),
                )
            );
            assert_eq!(usize::from(material.share_index), expected_index);
            assert!(!material.material_bytes.is_empty());

            let receipt = verify_experimental_multi_witness_recovery_share_material(
                &header,
                &transactions,
                &witness_seed,
                &witness_set,
                0,
                material,
            )
            .expect("share material should verify");
            assert_eq!(receipt, material.to_recovery_share_receipt());
        }
    }

    #[test]
    fn experimental_multi_witness_recovery_share_material_builds_and_verifies_for_four_of_six_gf256(
    ) {
        let (header, transactions) = sample_block_header_with_ordered_transactions(0x5e);
        let witness_seed = sample_guardian_witness_seed();
        let witness_set = sample_guardian_witness_set(vec![
            [0xc1u8; 32],
            [0xc2u8; 32],
            [0xc3u8; 32],
            [0xc4u8; 32],
            [0xc5u8; 32],
            [0xc6u8; 32],
        ]);
        let materials = build_experimental_multi_witness_recovery_share_materials(
            &header,
            &transactions,
            &witness_seed,
            &witness_set,
            0,
            sample_gf256_4_of_6_share_count(),
            sample_gf256_4_of_6_recovery_threshold(),
        )
        .expect("share materials");

        assert_eq!(
            materials.len(),
            usize::from(sample_gf256_4_of_6_share_count())
        );
        let expected_block_commitment_hash =
            canonical_block_commitment_hash(&header).expect("block commitment hash");
        for (expected_index, material) in materials.iter().enumerate() {
            assert_eq!(material.height, header.height);
            assert_eq!(
                material.block_commitment_hash,
                expected_block_commitment_hash
            );
            assert_eq!(
                material.coding,
                gf256_recovery_coding(
                    sample_gf256_4_of_6_share_count(),
                    sample_gf256_4_of_6_recovery_threshold(),
                )
            );
            assert_eq!(usize::from(material.share_index), expected_index);
            assert!(!material.material_bytes.is_empty());

            let receipt = verify_experimental_multi_witness_recovery_share_material(
                &header,
                &transactions,
                &witness_seed,
                &witness_set,
                0,
                material,
            )
            .expect("share material should verify");
            assert_eq!(receipt, material.to_recovery_share_receipt());
        }
    }

    #[test]
    fn experimental_multi_witness_recovery_share_material_builds_and_verifies_for_four_of_seven_gf256(
    ) {
        let (header, transactions) = sample_block_header_with_ordered_transactions(0x61);
        let witness_seed = sample_guardian_witness_seed();
        let witness_set = sample_guardian_witness_set(vec![
            [0xf1u8; 32],
            [0xf2u8; 32],
            [0xf3u8; 32],
            [0xf4u8; 32],
            [0xf5u8; 32],
            [0xf6u8; 32],
            [0xf7u8; 32],
        ]);
        let materials = build_experimental_multi_witness_recovery_share_materials(
            &header,
            &transactions,
            &witness_seed,
            &witness_set,
            0,
            sample_gf256_4_of_7_share_count(),
            sample_gf256_4_of_7_recovery_threshold(),
        )
        .expect("share materials");

        assert_eq!(
            materials.len(),
            usize::from(sample_gf256_4_of_7_share_count())
        );
        let expected_block_commitment_hash =
            canonical_block_commitment_hash(&header).expect("block commitment hash");
        for (expected_index, material) in materials.iter().enumerate() {
            assert_eq!(material.height, header.height);
            assert_eq!(
                material.block_commitment_hash,
                expected_block_commitment_hash
            );
            assert_eq!(
                material.coding,
                gf256_recovery_coding(
                    sample_gf256_4_of_7_share_count(),
                    sample_gf256_4_of_7_recovery_threshold(),
                )
            );
            assert_eq!(usize::from(material.share_index), expected_index);
            assert!(!material.material_bytes.is_empty());

            let receipt = verify_experimental_multi_witness_recovery_share_material(
                &header,
                &transactions,
                &witness_seed,
                &witness_set,
                0,
                material,
            )
            .expect("share material should verify");
            assert_eq!(receipt, material.to_recovery_share_receipt());
        }
    }

    #[test]
    fn experimental_multi_witness_recovery_share_material_reconstructs_publication_bundle_payload_from_three_of_four_shards(
    ) {
        let (header, transactions) = sample_block_header_with_ordered_transactions(0x52);
        let certificate =
            build_committed_surface_canonical_order_certificate(&header, &transactions)
                .expect("canonical order certificate");
        let witness_seed = sample_guardian_witness_seed();
        let witness_set = sample_guardian_witness_set(vec![
            [0x64u8; 32],
            [0x65u8; 32],
            [0x66u8; 32],
            [0x67u8; 32],
        ]);
        let materials = build_experimental_multi_witness_recovery_share_materials(
            &header,
            &transactions,
            &witness_seed,
            &witness_set,
            0,
            sample_parity_family_share_count(),
            sample_parity_family_recovery_threshold(),
        )
        .expect("share materials");

        let recovered = recover_recoverable_slot_payload_v3_from_share_materials(&[
            materials[0].clone(),
            materials[2].clone(),
            materials[3].clone(),
        ])
        .expect("payload should reconstruct from three of four parity-family shards");
        let expected_payload =
            build_recoverable_slot_payload_v3(&header, &transactions, &certificate)
                .expect("recoverable payload");
        let expected_transaction_bytes = transactions
            .iter()
            .map(|transaction| codec::to_bytes_canonical(transaction).expect("transaction bytes"))
            .collect::<Vec<_>>();
        let recovered_bundle: CanonicalOrderPublicationBundle =
            codec::from_bytes_canonical(&recovered.canonical_order_publication_bundle_bytes)
                .expect("decode recovered publication bundle");
        let rebuilt_close =
            ioi_types::app::verify_canonical_order_publication_bundle(&recovered_bundle)
                .expect("verify recovered publication bundle");

        assert_eq!(recovered.height, header.height);
        assert_eq!(recovered.view, header.view);
        assert_eq!(recovered.producer_account_id, header.producer_account_id);
        assert_eq!(
            recovered.block_commitment_hash,
            canonical_block_commitment_hash(&header).expect("block commitment hash")
        );
        assert_eq!(recovered.canonical_order_certificate, certificate);
        assert_eq!(
            recovered.ordered_transaction_bytes,
            expected_transaction_bytes
        );
        assert_eq!(
            recovered.canonical_order_publication_bundle_bytes,
            expected_payload.canonical_order_publication_bundle_bytes
        );
        assert_eq!(
            recovered_bundle.canonical_order_certificate,
            expected_payload.canonical_order_certificate
        );
        assert_eq!(rebuilt_close.height, header.height);
    }

    #[test]
    fn experimental_multi_witness_recovery_share_material_reconstructs_publication_bundle_payload_from_two_of_four_gf256_shards(
    ) {
        let (header, transactions) = sample_block_header_with_ordered_transactions(0x5a);
        let certificate =
            build_committed_surface_canonical_order_certificate(&header, &transactions)
                .expect("canonical order certificate");
        let witness_seed = sample_guardian_witness_seed();
        let witness_set = sample_guardian_witness_set(vec![
            [0x71u8; 32],
            [0x72u8; 32],
            [0x73u8; 32],
            [0x74u8; 32],
        ]);
        let materials = build_experimental_multi_witness_recovery_share_materials(
            &header,
            &transactions,
            &witness_seed,
            &witness_set,
            0,
            sample_gf256_2_of_4_share_count(),
            sample_gf256_2_of_4_recovery_threshold(),
        )
        .expect("share materials");

        let recovered = recover_recoverable_slot_payload_v3_from_share_materials(&[
            materials[1].clone(),
            materials[3].clone(),
        ])
        .expect("payload should reconstruct from two of four gf256 shards");
        let expected_payload =
            build_recoverable_slot_payload_v3(&header, &transactions, &certificate)
                .expect("recoverable payload");
        let expected_transaction_bytes = transactions
            .iter()
            .map(|transaction| codec::to_bytes_canonical(transaction).expect("transaction bytes"))
            .collect::<Vec<_>>();
        let recovered_bundle: CanonicalOrderPublicationBundle =
            codec::from_bytes_canonical(&recovered.canonical_order_publication_bundle_bytes)
                .expect("decode recovered publication bundle");
        let rebuilt_close =
            ioi_types::app::verify_canonical_order_publication_bundle(&recovered_bundle)
                .expect("verify recovered publication bundle");

        assert_eq!(recovered.height, header.height);
        assert_eq!(recovered.view, header.view);
        assert_eq!(recovered.producer_account_id, header.producer_account_id);
        assert_eq!(
            recovered.block_commitment_hash,
            canonical_block_commitment_hash(&header).expect("block commitment hash")
        );
        assert_eq!(recovered.canonical_order_certificate, certificate);
        assert_eq!(
            recovered.ordered_transaction_bytes,
            expected_transaction_bytes
        );
        assert_eq!(
            recovered.canonical_order_publication_bundle_bytes,
            expected_payload.canonical_order_publication_bundle_bytes
        );
        assert_eq!(
            recovered_bundle.canonical_order_certificate,
            expected_payload.canonical_order_certificate
        );
        assert_eq!(rebuilt_close.height, header.height);
    }

    #[test]
    fn experimental_multi_witness_recovery_share_material_reconstructs_publication_bundle_payload_from_three_of_five_gf256_shards(
    ) {
        let (header, transactions) = sample_block_header_with_ordered_transactions(0x5c);
        let certificate =
            build_committed_surface_canonical_order_certificate(&header, &transactions)
                .expect("canonical order certificate");
        let witness_seed = sample_guardian_witness_seed();
        let witness_set = sample_guardian_witness_set(vec![
            [0xa1u8; 32],
            [0xa2u8; 32],
            [0xa3u8; 32],
            [0xa4u8; 32],
            [0xa5u8; 32],
        ]);
        let materials = build_experimental_multi_witness_recovery_share_materials(
            &header,
            &transactions,
            &witness_seed,
            &witness_set,
            0,
            sample_gf256_3_of_5_share_count(),
            sample_gf256_3_of_5_recovery_threshold(),
        )
        .expect("share materials");

        let recovered = recover_recoverable_slot_payload_v3_from_share_materials(&[
            materials[0].clone(),
            materials[3].clone(),
            materials[4].clone(),
        ])
        .expect("payload should reconstruct from three of five gf256 shards");
        let expected_payload =
            build_recoverable_slot_payload_v3(&header, &transactions, &certificate)
                .expect("recoverable payload");
        let expected_transaction_bytes = transactions
            .iter()
            .map(|transaction| codec::to_bytes_canonical(transaction).expect("transaction bytes"))
            .collect::<Vec<_>>();
        let recovered_bundle: CanonicalOrderPublicationBundle =
            codec::from_bytes_canonical(&recovered.canonical_order_publication_bundle_bytes)
                .expect("decode recovered publication bundle");
        let rebuilt_close =
            ioi_types::app::verify_canonical_order_publication_bundle(&recovered_bundle)
                .expect("verify recovered publication bundle");

        assert_eq!(recovered.height, header.height);
        assert_eq!(recovered.view, header.view);
        assert_eq!(recovered.producer_account_id, header.producer_account_id);
        assert_eq!(
            recovered.block_commitment_hash,
            canonical_block_commitment_hash(&header).expect("block commitment hash")
        );
        assert_eq!(recovered.canonical_order_certificate, certificate);
        assert_eq!(
            recovered.ordered_transaction_bytes,
            expected_transaction_bytes
        );
        assert_eq!(
            recovered.canonical_order_publication_bundle_bytes,
            expected_payload.canonical_order_publication_bundle_bytes
        );
        assert_eq!(
            recovered_bundle.canonical_order_certificate,
            expected_payload.canonical_order_certificate
        );
        assert_eq!(rebuilt_close.height, header.height);
    }

    #[test]
    fn experimental_multi_witness_recovery_share_material_reconstructs_publication_bundle_payload_from_three_of_seven_gf256_shards(
    ) {
        let (header, transactions) = sample_block_header_with_ordered_transactions(0x5d);
        let certificate =
            build_committed_surface_canonical_order_certificate(&header, &transactions)
                .expect("canonical order certificate");
        let witness_seed = sample_guardian_witness_seed();
        let witness_set = sample_guardian_witness_set(vec![
            [0xb1u8; 32],
            [0xb2u8; 32],
            [0xb3u8; 32],
            [0xb4u8; 32],
            [0xb5u8; 32],
            [0xb6u8; 32],
            [0xb7u8; 32],
        ]);
        let materials = build_experimental_multi_witness_recovery_share_materials(
            &header,
            &transactions,
            &witness_seed,
            &witness_set,
            0,
            sample_gf256_3_of_7_share_count(),
            sample_gf256_3_of_7_recovery_threshold(),
        )
        .expect("share materials");

        let recovered = recover_recoverable_slot_payload_v3_from_share_materials(&[
            materials[0].clone(),
            materials[3].clone(),
            materials[6].clone(),
        ])
        .expect("payload should reconstruct from three of seven gf256 shards");
        let expected_payload =
            build_recoverable_slot_payload_v3(&header, &transactions, &certificate)
                .expect("recoverable payload");
        let expected_transaction_bytes = transactions
            .iter()
            .map(|transaction| codec::to_bytes_canonical(transaction).expect("transaction bytes"))
            .collect::<Vec<_>>();
        let recovered_bundle: CanonicalOrderPublicationBundle =
            codec::from_bytes_canonical(&recovered.canonical_order_publication_bundle_bytes)
                .expect("decode recovered publication bundle");
        let rebuilt_close =
            ioi_types::app::verify_canonical_order_publication_bundle(&recovered_bundle)
                .expect("verify recovered publication bundle");

        assert_eq!(recovered.height, header.height);
        assert_eq!(recovered.view, header.view);
        assert_eq!(recovered.producer_account_id, header.producer_account_id);
        assert_eq!(
            recovered.block_commitment_hash,
            canonical_block_commitment_hash(&header).expect("block commitment hash")
        );
        assert_eq!(recovered.canonical_order_certificate, certificate);
        assert_eq!(
            recovered.ordered_transaction_bytes,
            expected_transaction_bytes
        );
        assert_eq!(
            recovered.canonical_order_publication_bundle_bytes,
            expected_payload.canonical_order_publication_bundle_bytes
        );
        assert_eq!(
            recovered_bundle.canonical_order_certificate,
            expected_payload.canonical_order_certificate
        );
        assert_eq!(rebuilt_close.height, header.height);
    }

    #[test]
    fn experimental_multi_witness_recovery_share_material_reconstructs_full_positive_close_surface_from_three_of_seven_gf256_shards(
    ) {
        let (header, transactions) = sample_block_header_with_ordered_transactions(0x5e);
        let certificate =
            build_committed_surface_canonical_order_certificate(&header, &transactions)
                .expect("canonical order certificate");
        let witness_seed = sample_guardian_witness_seed();
        let witness_set = sample_guardian_witness_set(vec![
            [0xc1u8; 32],
            [0xc2u8; 32],
            [0xc3u8; 32],
            [0xc4u8; 32],
            [0xc5u8; 32],
            [0xc6u8; 32],
            [0xc7u8; 32],
        ]);
        let materials = build_experimental_multi_witness_recovery_share_materials(
            &header,
            &transactions,
            &witness_seed,
            &witness_set,
            0,
            sample_gf256_3_of_7_share_count(),
            sample_gf256_3_of_7_recovery_threshold(),
        )
        .expect("share materials");

        let support_materials = [
            materials[0].clone(),
            materials[3].clone(),
            materials[6].clone(),
        ];
        let (recovered_payload, recovered_bundle, recovered_close) =
            recover_canonical_order_artifact_surface_from_share_materials(&support_materials)
                .expect(
                "full positive close surface should reconstruct from three of seven gf256 shards",
            );
        let (recovered_full_surface, _, _, recovered_surface_entries) =
            recover_full_canonical_order_surface_from_share_materials(&support_materials)
                .expect(
                    "full extractable bulletin surface should reconstruct from three of seven gf256 shards",
                );
        let expected_payload =
            build_recoverable_slot_payload_v4(&header, &transactions, &certificate)
                .expect("recoverable payload v4");
        let expected_full_surface =
            build_recoverable_slot_payload_v5(&header, &transactions, &certificate)
                .expect("recoverable payload v5");
        let expected_bundle: CanonicalOrderPublicationBundle =
            codec::from_bytes_canonical(&expected_payload.canonical_order_publication_bundle_bytes)
                .expect("decode expected publication bundle");
        let expected_close =
            ioi_types::app::verify_canonical_order_publication_bundle(&expected_bundle)
                .expect("verify expected publication bundle");
        let expected_surface = expected_bundle.bulletin_entries.clone();
        let recovered_object = build_recovered_publication_bundle(&support_materials)
            .expect("recovered publication bundle object");

        assert_eq!(recovered_payload, expected_payload);
        assert_eq!(recovered_full_surface, expected_full_surface);
        assert_eq!(recovered_bundle, expected_bundle);
        assert_eq!(recovered_close, expected_close);
        assert_eq!(recovered_surface_entries, expected_surface);
        assert_eq!(
            recovered_object.recoverable_slot_payload_hash,
            canonical_recoverable_slot_payload_v4_hash(&expected_payload)
                .expect("recoverable payload v4 hash")
        );
        assert_eq!(
            recovered_object.recoverable_full_surface_hash,
            canonical_recoverable_slot_payload_v5_hash(&expected_full_surface)
                .expect("recoverable payload v5 hash")
        );
        assert_eq!(
            recovered_object.canonical_bulletin_close_hash,
            canonical_bulletin_close_hash(&expected_close).expect("canonical bulletin close hash")
        );
    }

    #[test]
    fn experimental_multi_witness_recovery_recovered_surfaces_chain_publication_frontiers_across_two_slots(
    ) {
        let witness_seed = sample_guardian_witness_seed();
        let witness_set = sample_guardian_witness_set(vec![
            [0xe1u8; 32],
            [0xe2u8; 32],
            [0xe3u8; 32],
            [0xe4u8; 32],
            [0xe5u8; 32],
            [0xe6u8; 32],
            [0xe7u8; 32],
        ]);

        let mut base_header_a = sample_block_header();
        base_header_a.height = 1;
        base_header_a.timestamp += 1;
        base_header_a.timestamp_ms += 1_000;
        let (header_a, transactions_a) =
            sample_block_header_with_ordered_transactions_from_header(base_header_a, 0x64);
        let materials_a = build_experimental_multi_witness_recovery_share_materials(
            &header_a,
            &transactions_a,
            &witness_seed,
            &witness_set,
            0,
            sample_gf256_3_of_7_share_count(),
            sample_gf256_3_of_7_recovery_threshold(),
        )
        .expect("slot-a share materials");
        let support_a = [
            materials_a[0].clone(),
            materials_a[3].clone(),
            materials_a[6].clone(),
        ];
        let (recovered_surface_a, _, _, _) =
            recover_full_canonical_order_surface_from_share_materials(&support_a)
                .expect("slot-a recovered full extractable surface");
        let recovered_header_a = recovered_publication_frontier_header(&recovered_surface_a);
        let frontier_a = build_publication_frontier(&recovered_header_a, None)
            .expect("slot-a recovered publication frontier");
        ioi_types::app::verify_publication_frontier(&recovered_header_a, &frontier_a, None)
            .expect("slot-a recovered publication frontier should verify");

        let mut base_header_b = sample_block_header();
        base_header_b.height = header_a.height + 1;
        base_header_b.view = header_a.view + 1;
        base_header_b.parent_hash =
            canonical_block_commitment_hash(&header_a).expect("slot-a block commitment hash");
        base_header_b.parent_state_root = header_a.state_root.clone();
        base_header_b.timestamp = header_a.timestamp + 1;
        base_header_b.timestamp_ms = header_a.timestamp_ms + 1_000;
        base_header_b.parent_qc.height = header_a.height;
        base_header_b.parent_qc.view = header_a.view;
        base_header_b.parent_qc.block_hash = base_header_b.parent_hash;
        let (header_b, transactions_b) =
            sample_block_header_with_ordered_transactions_from_header(base_header_b, 0x65);
        let materials_b = build_experimental_multi_witness_recovery_share_materials(
            &header_b,
            &transactions_b,
            &witness_seed,
            &witness_set,
            0,
            sample_gf256_3_of_7_share_count(),
            sample_gf256_3_of_7_recovery_threshold(),
        )
        .expect("slot-b share materials");
        let support_b = [
            materials_b[0].clone(),
            materials_b[3].clone(),
            materials_b[6].clone(),
        ];
        let (recovered_surface_b, _, _, _) =
            recover_full_canonical_order_surface_from_share_materials(&support_b)
                .expect("slot-b recovered full extractable surface");
        let recovered_header_b = recovered_publication_frontier_header(&recovered_surface_b);
        let frontier_b = build_publication_frontier(&recovered_header_b, Some(&frontier_a))
            .expect("slot-b recovered publication frontier");
        ioi_types::app::verify_publication_frontier(
            &recovered_header_b,
            &frontier_b,
            Some(&frontier_a),
        )
        .expect("slot-b recovered publication frontier should verify");

        assert_eq!(frontier_a.height, 1);
        assert_eq!(frontier_a.parent_frontier_hash, [0u8; 32]);
        assert_eq!(frontier_b.height, 2);
        assert_eq!(frontier_b.counter, frontier_a.counter + 1);
        assert_eq!(
            frontier_b.parent_frontier_hash,
            ioi_types::app::canonical_publication_frontier_hash(&frontier_a)
                .expect("slot-a publication frontier hash")
        );
    }

    #[test]
    fn experimental_multi_witness_recovery_share_material_reconstructs_publication_bundle_payload_from_four_of_six_gf256_shards(
    ) {
        let (header, transactions) = sample_block_header_with_ordered_transactions(0x5f);
        let certificate =
            build_committed_surface_canonical_order_certificate(&header, &transactions)
                .expect("canonical order certificate");
        let witness_seed = sample_guardian_witness_seed();
        let witness_set = sample_guardian_witness_set(vec![
            [0xd1u8; 32],
            [0xd2u8; 32],
            [0xd3u8; 32],
            [0xd4u8; 32],
            [0xd5u8; 32],
            [0xd6u8; 32],
        ]);
        let materials = build_experimental_multi_witness_recovery_share_materials(
            &header,
            &transactions,
            &witness_seed,
            &witness_set,
            0,
            sample_gf256_4_of_6_share_count(),
            sample_gf256_4_of_6_recovery_threshold(),
        )
        .expect("share materials");

        let recovered = recover_recoverable_slot_payload_v3_from_share_materials(&[
            materials[0].clone(),
            materials[2].clone(),
            materials[4].clone(),
            materials[5].clone(),
        ])
        .expect("payload should reconstruct from four of six gf256 shards");
        let expected_payload =
            build_recoverable_slot_payload_v3(&header, &transactions, &certificate)
                .expect("recoverable payload");
        let expected_transaction_bytes = transactions
            .iter()
            .map(|transaction| codec::to_bytes_canonical(transaction).expect("transaction bytes"))
            .collect::<Vec<_>>();
        let recovered_bundle: CanonicalOrderPublicationBundle =
            codec::from_bytes_canonical(&recovered.canonical_order_publication_bundle_bytes)
                .expect("decode recovered publication bundle");
        let rebuilt_close =
            ioi_types::app::verify_canonical_order_publication_bundle(&recovered_bundle)
                .expect("verify recovered publication bundle");

        assert_eq!(recovered.height, header.height);
        assert_eq!(recovered.view, header.view);
        assert_eq!(recovered.producer_account_id, header.producer_account_id);
        assert_eq!(
            recovered.block_commitment_hash,
            canonical_block_commitment_hash(&header).expect("block commitment hash")
        );
        assert_eq!(recovered.canonical_order_certificate, certificate);
        assert_eq!(
            recovered.ordered_transaction_bytes,
            expected_transaction_bytes
        );
        assert_eq!(
            recovered.canonical_order_publication_bundle_bytes,
            expected_payload.canonical_order_publication_bundle_bytes
        );
        assert_eq!(
            recovered_bundle.canonical_order_certificate,
            expected_payload.canonical_order_certificate
        );
        assert_eq!(rebuilt_close.height, header.height);
    }

    #[test]
    fn experimental_multi_witness_recovery_share_material_reconstructs_publication_bundle_payload_from_four_of_seven_gf256_shards(
    ) {
        let (header, transactions) = sample_block_header_with_ordered_transactions(0x62);
        let certificate =
            build_committed_surface_canonical_order_certificate(&header, &transactions)
                .expect("canonical order certificate");
        let witness_seed = sample_guardian_witness_seed();
        let witness_set = sample_guardian_witness_set(vec![
            [0x11u8; 32],
            [0x12u8; 32],
            [0x13u8; 32],
            [0x14u8; 32],
            [0x15u8; 32],
            [0x16u8; 32],
            [0x17u8; 32],
        ]);
        let materials = build_experimental_multi_witness_recovery_share_materials(
            &header,
            &transactions,
            &witness_seed,
            &witness_set,
            0,
            sample_gf256_4_of_7_share_count(),
            sample_gf256_4_of_7_recovery_threshold(),
        )
        .expect("share materials");

        let recovered = recover_recoverable_slot_payload_v3_from_share_materials(&[
            materials[0].clone(),
            materials[2].clone(),
            materials[4].clone(),
            materials[6].clone(),
        ])
        .expect("payload should reconstruct from four of seven gf256 shards");
        let expected_payload =
            build_recoverable_slot_payload_v3(&header, &transactions, &certificate)
                .expect("recoverable payload");
        let expected_transaction_bytes = transactions
            .iter()
            .map(|transaction| codec::to_bytes_canonical(transaction).expect("transaction bytes"))
            .collect::<Vec<_>>();
        let recovered_bundle: CanonicalOrderPublicationBundle =
            codec::from_bytes_canonical(&recovered.canonical_order_publication_bundle_bytes)
                .expect("decode recovered publication bundle");
        let rebuilt_close =
            ioi_types::app::verify_canonical_order_publication_bundle(&recovered_bundle)
                .expect("verify recovered publication bundle");

        assert_eq!(recovered.height, header.height);
        assert_eq!(recovered.view, header.view);
        assert_eq!(recovered.producer_account_id, header.producer_account_id);
        assert_eq!(
            recovered.block_commitment_hash,
            canonical_block_commitment_hash(&header).expect("block commitment hash")
        );
        assert_eq!(recovered.canonical_order_certificate, certificate);
        assert_eq!(
            recovered.ordered_transaction_bytes,
            expected_transaction_bytes
        );
        assert_eq!(
            recovered.canonical_order_publication_bundle_bytes,
            expected_payload.canonical_order_publication_bundle_bytes
        );
        assert_eq!(
            recovered_bundle.canonical_order_certificate,
            expected_payload.canonical_order_certificate
        );
        assert_eq!(rebuilt_close.height, header.height);
    }

    #[test]
    fn experimental_multi_witness_recovery_share_material_commitments_change_with_transaction_bytes(
    ) {
        let (header_a, transactions_a) = sample_block_header_with_ordered_transactions(0x53);
        let (header_b, transactions_b) = sample_block_header_with_ordered_transactions(0x54);
        let witness_seed = sample_guardian_witness_seed();
        let witness_set = sample_guardian_witness_set(vec![
            [0x68u8; 32],
            [0x69u8; 32],
            [0x6au8; 32],
            [0x6bu8; 32],
        ]);
        let materials_a = build_experimental_multi_witness_recovery_share_materials(
            &header_a,
            &transactions_a,
            &witness_seed,
            &witness_set,
            0,
            sample_gf256_2_of_4_share_count(),
            sample_gf256_2_of_4_recovery_threshold(),
        )
        .expect("share materials a");
        let materials_b = build_experimental_multi_witness_recovery_share_materials(
            &header_b,
            &transactions_b,
            &witness_seed,
            &witness_set,
            0,
            sample_gf256_2_of_4_share_count(),
            sample_gf256_2_of_4_recovery_threshold(),
        )
        .expect("share materials b");

        let commitments_a = materials_a
            .iter()
            .map(|material| material.share_commitment_hash)
            .collect::<Vec<_>>();
        let commitments_b = materials_b
            .iter()
            .map(|material| material.share_commitment_hash)
            .collect::<Vec<_>>();
        let shard_bytes_a = materials_a
            .iter()
            .map(|material| material.material_bytes.clone())
            .collect::<Vec<_>>();
        let shard_bytes_b = materials_b
            .iter()
            .map(|material| material.material_bytes.clone())
            .collect::<Vec<_>>();

        assert_ne!(commitments_a, commitments_b);
        assert_ne!(shard_bytes_a, shard_bytes_b);
    }

    #[test]
    fn experimental_multi_witness_recovery_share_material_coded_family_subset_conformance_holds_across_bounded_geometries(
    ) {
        for (transaction_seed, manifest_seed, share_count, recovery_threshold) in [
            (0x57, 0x63, 3, 2),
            (0x59, 0x69, 4, 3),
            (0x5a, 0x71, 4, 2),
            (0x5c, 0xa1, 5, 3),
            (0x5d, 0xb1, 7, 3),
            (0x5f, 0xd1, 6, 4),
            (0x62, 0x11, 7, 4),
        ] {
            assert_coded_recovery_family_subset_conformance_case(
                transaction_seed,
                manifest_seed,
                share_count,
                recovery_threshold,
            );
        }
    }

    #[test]
    fn experimental_multi_witness_recovery_share_material_coded_family_commitments_are_deterministic_and_input_sensitive(
    ) {
        for (
            transaction_seed,
            manifest_seed,
            alternate_manifest_seed,
            share_count,
            recovery_threshold,
        ) in [
            (0x49, 0x52, 0x62, 3, 2),
            (0x4d, 0x56, 0x66, 4, 3),
            (0x53, 0x68, 0x78, 4, 2),
            (0x5d, 0xb1, 0xc1, 7, 3),
            (0x62, 0x11, 0x21, 7, 4),
        ] {
            assert_coded_recovery_family_commitment_determinism_case(
                transaction_seed,
                manifest_seed,
                alternate_manifest_seed,
                share_count,
                recovery_threshold,
            );
        }
    }

    #[test]
    fn experimental_multi_witness_recovery_binding_assignments_build_for_gf256_shape() {
        let (header, transactions) = sample_block_header_with_ordered_transactions(0x58);
        let witness_seed = sample_guardian_witness_seed();
        let witness_set = sample_guardian_witness_set(vec![
            [0x81u8; 32],
            [0x82u8; 32],
            [0x83u8; 32],
            [0x84u8; 32],
        ]);
        let assignments = derive_guardian_witness_assignments(
            &witness_seed,
            &witness_set,
            header.producer_account_id,
            header.height,
            header.view,
            0,
            sample_gf256_2_of_4_share_count(),
        )
        .expect("derive witness assignments");
        let plan = build_experimental_multi_witness_recovery_plan_from_assignments(
            &header,
            &transactions,
            witness_seed.epoch,
            assignments,
            0,
            sample_gf256_2_of_4_recovery_threshold(),
        )
        .expect("build multi-witness recovery plan");
        let (capsule, binding_assignments) =
            build_experimental_multi_witness_recovery_binding_assignments(header.height, &plan)
                .expect("build multi-witness recovery bindings");
        let recovery_capsule_hash =
            canonical_recovery_capsule_hash(&capsule).expect("recovery capsule hash");
        let distinct_manifests = binding_assignments
            .iter()
            .map(|assignment| assignment.witness_manifest_hash)
            .collect::<std::collections::BTreeSet<_>>();
        let distinct_share_commitments = binding_assignments
            .iter()
            .map(|assignment| assignment.recovery_binding.share_commitment_hash)
            .collect::<std::collections::BTreeSet<_>>();

        assert_eq!(
            capsule.coding,
            gf256_recovery_coding(
                sample_gf256_2_of_4_share_count(),
                sample_gf256_2_of_4_recovery_threshold(),
            )
        );
        assert_eq!(
            capsule.coding.recovery_threshold,
            sample_gf256_2_of_4_recovery_threshold()
        );
        assert_eq!(
            binding_assignments.len(),
            usize::from(sample_gf256_2_of_4_share_count())
        );
        assert_eq!(distinct_manifests.len(), binding_assignments.len());
        assert_eq!(distinct_share_commitments.len(), binding_assignments.len());
        assert!(binding_assignments.iter().all(|assignment| {
            assignment.recovery_binding.recovery_capsule_hash == recovery_capsule_hash
        }));
    }

    #[test]
    fn experimental_multi_witness_recovery_binding_assignments_build_for_three_of_five_gf256_shape()
    {
        let (header, transactions) = sample_block_header_with_ordered_transactions(0x5d);
        let witness_seed = sample_guardian_witness_seed();
        let witness_set = sample_guardian_witness_set(vec![
            [0xb1u8; 32],
            [0xb2u8; 32],
            [0xb3u8; 32],
            [0xb4u8; 32],
            [0xb5u8; 32],
        ]);
        let assignments = derive_guardian_witness_assignments(
            &witness_seed,
            &witness_set,
            header.producer_account_id,
            header.height,
            header.view,
            0,
            sample_gf256_3_of_5_share_count(),
        )
        .expect("derive witness assignments");
        let plan = build_experimental_multi_witness_recovery_plan_from_assignments(
            &header,
            &transactions,
            witness_seed.epoch,
            assignments,
            0,
            sample_gf256_3_of_5_recovery_threshold(),
        )
        .expect("build multi-witness recovery plan");
        let (capsule, binding_assignments) =
            build_experimental_multi_witness_recovery_binding_assignments(header.height, &plan)
                .expect("build multi-witness recovery bindings");
        let recovery_capsule_hash =
            canonical_recovery_capsule_hash(&capsule).expect("recovery capsule hash");
        let distinct_manifests = binding_assignments
            .iter()
            .map(|assignment| assignment.witness_manifest_hash)
            .collect::<std::collections::BTreeSet<_>>();
        let distinct_share_commitments = binding_assignments
            .iter()
            .map(|assignment| assignment.recovery_binding.share_commitment_hash)
            .collect::<std::collections::BTreeSet<_>>();

        assert_eq!(
            capsule.coding,
            gf256_recovery_coding(
                sample_gf256_3_of_5_share_count(),
                sample_gf256_3_of_5_recovery_threshold(),
            )
        );
        assert_eq!(
            capsule.coding.recovery_threshold,
            sample_gf256_3_of_5_recovery_threshold()
        );
        assert_eq!(
            binding_assignments.len(),
            usize::from(sample_gf256_3_of_5_share_count())
        );
        assert_eq!(distinct_manifests.len(), binding_assignments.len());
        assert_eq!(distinct_share_commitments.len(), binding_assignments.len());
        assert!(binding_assignments.iter().all(|assignment| {
            assignment.recovery_binding.recovery_capsule_hash == recovery_capsule_hash
        }));
    }

    #[test]
    fn experimental_multi_witness_recovery_binding_assignments_build_for_four_of_six_gf256_shape() {
        let (header, transactions) = sample_block_header_with_ordered_transactions(0x60);
        let witness_seed = sample_guardian_witness_seed();
        let witness_set = sample_guardian_witness_set(vec![
            [0xe1u8; 32],
            [0xe2u8; 32],
            [0xe3u8; 32],
            [0xe4u8; 32],
            [0xe5u8; 32],
            [0xe6u8; 32],
        ]);
        let assignments = derive_guardian_witness_assignments(
            &witness_seed,
            &witness_set,
            header.producer_account_id,
            header.height,
            header.view,
            0,
            sample_gf256_4_of_6_share_count(),
        )
        .expect("derive witness assignments");
        let plan = build_experimental_multi_witness_recovery_plan_from_assignments(
            &header,
            &transactions,
            witness_seed.epoch,
            assignments,
            0,
            sample_gf256_4_of_6_recovery_threshold(),
        )
        .expect("build multi-witness recovery plan");
        let (capsule, binding_assignments) =
            build_experimental_multi_witness_recovery_binding_assignments(header.height, &plan)
                .expect("build multi-witness recovery bindings");
        let recovery_capsule_hash =
            canonical_recovery_capsule_hash(&capsule).expect("recovery capsule hash");
        let distinct_manifests = binding_assignments
            .iter()
            .map(|assignment| assignment.witness_manifest_hash)
            .collect::<std::collections::BTreeSet<_>>();
        let distinct_share_commitments = binding_assignments
            .iter()
            .map(|assignment| assignment.recovery_binding.share_commitment_hash)
            .collect::<std::collections::BTreeSet<_>>();

        assert_eq!(
            capsule.coding,
            gf256_recovery_coding(
                sample_gf256_4_of_6_share_count(),
                sample_gf256_4_of_6_recovery_threshold(),
            )
        );
        assert_eq!(
            capsule.coding.recovery_threshold,
            sample_gf256_4_of_6_recovery_threshold()
        );
        assert_eq!(
            binding_assignments.len(),
            usize::from(sample_gf256_4_of_6_share_count())
        );
        assert_eq!(distinct_manifests.len(), binding_assignments.len());
        assert_eq!(distinct_share_commitments.len(), binding_assignments.len());
        assert!(binding_assignments.iter().all(|assignment| {
            assignment.recovery_binding.recovery_capsule_hash == recovery_capsule_hash
        }));
    }

    #[test]
    fn experimental_multi_witness_recovery_binding_assignments_build_for_four_of_seven_gf256_shape()
    {
        let (header, transactions) = sample_block_header_with_ordered_transactions(0x63);
        let witness_seed = sample_guardian_witness_seed();
        let witness_set = sample_guardian_witness_set(vec![
            [0x21u8; 32],
            [0x22u8; 32],
            [0x23u8; 32],
            [0x24u8; 32],
            [0x25u8; 32],
            [0x26u8; 32],
            [0x27u8; 32],
        ]);
        let assignments = derive_guardian_witness_assignments(
            &witness_seed,
            &witness_set,
            header.producer_account_id,
            header.height,
            header.view,
            0,
            sample_gf256_4_of_7_share_count(),
        )
        .expect("derive witness assignments");
        let plan = build_experimental_multi_witness_recovery_plan_from_assignments(
            &header,
            &transactions,
            witness_seed.epoch,
            assignments,
            0,
            sample_gf256_4_of_7_recovery_threshold(),
        )
        .expect("build multi-witness recovery plan");
        let (capsule, binding_assignments) =
            build_experimental_multi_witness_recovery_binding_assignments(header.height, &plan)
                .expect("build multi-witness recovery bindings");
        let recovery_capsule_hash =
            canonical_recovery_capsule_hash(&capsule).expect("recovery capsule hash");
        let distinct_manifests = binding_assignments
            .iter()
            .map(|assignment| assignment.witness_manifest_hash)
            .collect::<std::collections::BTreeSet<_>>();
        let distinct_share_commitments = binding_assignments
            .iter()
            .map(|assignment| assignment.recovery_binding.share_commitment_hash)
            .collect::<std::collections::BTreeSet<_>>();

        assert_eq!(
            capsule.coding,
            gf256_recovery_coding(
                sample_gf256_4_of_7_share_count(),
                sample_gf256_4_of_7_recovery_threshold(),
            )
        );
        assert_eq!(
            capsule.coding.recovery_threshold,
            sample_gf256_4_of_7_recovery_threshold()
        );
        assert_eq!(
            binding_assignments.len(),
            usize::from(sample_gf256_4_of_7_share_count())
        );
        assert_eq!(distinct_manifests.len(), binding_assignments.len());
        assert_eq!(distinct_share_commitments.len(), binding_assignments.len());
        assert!(binding_assignments.iter().all(|assignment| {
            assignment.recovery_binding.recovery_capsule_hash == recovery_capsule_hash
        }));
    }

    #[test]
    fn experimental_multi_witness_recovery_share_material_stays_transparent_outside_coded_shapes() {
        let mut header = sample_block_header();
        header.transactions_root =
            ioi_types::app::canonical_transaction_root_from_hashes(&[]).expect("transactions root");
        let witness_seed = sample_guardian_witness_seed();
        let witness_set = sample_guardian_witness_set(vec![
            [0x81u8; 32],
            [0x82u8; 32],
            [0x83u8; 32],
            [0x84u8; 32],
            [0x85u8; 32],
        ]);
        let materials = build_experimental_multi_witness_recovery_share_materials(
            &header,
            &[],
            &witness_seed,
            &witness_set,
            0,
            5,
            5,
        )
        .expect("share materials");

        assert_eq!(materials.len(), 5);
        assert!(materials.iter().all(|material| {
            material.coding.family == RecoveryCodingFamily::TransparentCommittedSurfaceV1
        }));
    }

    #[test]
    fn experimental_multi_witness_recovery_share_material_rejects_tampered_material_bytes() {
        let mut header = sample_block_header();
        header.transactions_root =
            ioi_types::app::canonical_transaction_root_from_hashes(&[]).expect("transactions root");
        let witness_seed = sample_guardian_witness_seed();
        let witness_set =
            sample_guardian_witness_set(vec![[0x71u8; 32], [0x72u8; 32], [0x73u8; 32]]);
        let mut material = build_experimental_multi_witness_recovery_share_materials(
            &header,
            &[],
            &witness_seed,
            &witness_set,
            0,
            3,
            2,
        )
        .expect("share materials")
        .into_iter()
        .next()
        .expect("first share material");
        material.material_bytes[0] ^= 0xFF;

        let error = verify_experimental_multi_witness_recovery_share_material(
            &header,
            &[],
            &witness_seed,
            &witness_set,
            0,
            &material,
        )
        .expect_err("tampered share material should fail verification");

        assert!(
            error
                .to_string()
                .contains("deterministic committed-surface materialization"),
            "unexpected error: {error:#}"
        );
    }

    #[test]
    fn canonicalize_observer_sealed_finality_proof_rewrites_invalid_close_into_abort() {
        let header = sample_block_header();
        let policy = AsymptotePolicy {
            epoch: 9,
            observer_sealing_mode: AsymptoteObserverSealingMode::CanonicalChallengeV1,
            observer_challenge_window_ms: 500,
            ..Default::default()
        };
        let assignment = ioi_types::app::AsymptoteObserverAssignment {
            epoch: 9,
            producer_account_id: header.producer_account_id,
            height: header.height,
            view: header.view,
            round: 0,
            observer_account_id: AccountId([42u8; 32]),
        };
        let transcripts = vec![AsymptoteObserverTranscript {
            statement: AsymptoteObserverStatement {
                epoch: 9,
                assignment: assignment.clone(),
                block_hash: [50u8; 32],
                guardian_manifest_hash: [51u8; 32],
                guardian_decision_hash: [52u8; 32],
                guardian_counter: 53,
                guardian_trace_hash: [54u8; 32],
                guardian_measurement_root: [55u8; 32],
                guardian_checkpoint_root: [56u8; 32],
                verdict: ioi_types::app::AsymptoteObserverVerdict::Ok,
                veto_kind: None,
                evidence_hash: [57u8; 32],
            },
            guardian_certificate: header
                .guardian_certificate
                .clone()
                .expect("sample header must carry guardian certificate"),
        }];
        let assignments_hash =
            canonical_asymptote_observer_assignments_hash(&[assignment]).expect("assignment hash");
        let transcripts_root =
            canonical_asymptote_observer_transcripts_hash(&transcripts).expect("transcript root");
        let empty_challenges: Vec<AsymptoteObserverChallenge> = Vec::new();
        let empty_challenges_root = canonical_asymptote_observer_challenges_hash(&empty_challenges)
            .expect("empty challenge root");
        let invalid_close = AsymptoteObserverCanonicalClose {
            epoch: 9,
            height: header.height,
            view: header.view,
            assignments_hash,
            transcripts_root,
            challenges_root: empty_challenges_root,
            transcript_count: 1,
            challenge_count: 1,
            challenge_cutoff_timestamp_ms: header.timestamp_ms_or_legacy().saturating_add(500),
        };
        let mut proof = SealedFinalityProof {
            epoch: 9,
            finality_tier: ioi_types::app::FinalityTier::SealedFinal,
            collapse_state: ioi_types::app::CollapseState::SealedFinal,
            guardian_manifest_hash: [58u8; 32],
            guardian_decision_hash: [59u8; 32],
            guardian_counter: 60,
            guardian_trace_hash: [61u8; 32],
            guardian_measurement_root: [62u8; 32],
            policy_hash: [63u8; 32],
            witness_certificates: Vec::new(),
            observer_certificates: Vec::new(),
            observer_close_certificate: None,
            observer_transcripts: transcripts.clone(),
            observer_challenges: Vec::new(),
            observer_transcript_commitment: Some(AsymptoteObserverTranscriptCommitment {
                epoch: 9,
                height: header.height,
                view: header.view,
                assignments_hash,
                transcripts_root,
                transcript_count: 1,
            }),
            observer_challenge_commitment: Some(AsymptoteObserverChallengeCommitment {
                epoch: 9,
                height: header.height,
                view: header.view,
                challenges_root: empty_challenges_root,
                challenge_count: 0,
            }),
            observer_canonical_close: Some(invalid_close.clone()),
            observer_canonical_abort: None,
            veto_proofs: Vec::new(),
            divergence_signals: Vec::new(),
            proof_signature: SignatureProof::default(),
        };

        let artifacts =
            canonicalize_observer_sealed_finality_proof(&header, &policy, [64u8; 32], &mut proof)
                .expect("canonicalization should succeed")
                .expect("invalid close should still yield canonical artifacts");

        assert_eq!(proof.finality_tier, ioi_types::app::FinalityTier::BaseFinal);
        assert_eq!(proof.collapse_state, ioi_types::app::CollapseState::Abort);
        assert!(proof.observer_canonical_close.is_none());
        assert!(proof.observer_canonical_abort.is_some());
        let invalid_close_challenge = proof
            .observer_challenges
            .iter()
            .find(|challenge| {
                challenge.kind == AsymptoteObserverChallengeKind::InvalidCanonicalClose
            })
            .expect("invalid close challenge inserted");
        assert_eq!(
            invalid_close_challenge.canonical_close.as_ref(),
            Some(&invalid_close)
        );
        assert_eq!(artifacts.canonical_close, None);
        assert!(artifacts.canonical_abort.is_some());
    }

    #[tokio::test]
    async fn publish_canonical_observer_abort_artifacts_enqueues_transcript_challenge_and_abort() {
        let assignment = ioi_types::app::AsymptoteObserverAssignment {
            epoch: 9,
            producer_account_id: AccountId([21u8; 32]),
            height: 11,
            view: 4,
            round: 0,
            observer_account_id: AccountId([22u8; 32]),
        };
        let observation_request = ioi_types::app::AsymptoteObserverObservationRequest {
            epoch: 9,
            assignment: assignment.clone(),
            block_hash: [23u8; 32],
            guardian_manifest_hash: [24u8; 32],
            guardian_decision_hash: [25u8; 32],
            guardian_counter: 26,
            guardian_trace_hash: [27u8; 32],
            guardian_measurement_root: [28u8; 32],
            guardian_checkpoint_root: [29u8; 32],
        };
        let transcript = AsymptoteObserverTranscript {
            statement: AsymptoteObserverStatement {
                epoch: 9,
                assignment: assignment.clone(),
                block_hash: [23u8; 32],
                guardian_manifest_hash: [24u8; 32],
                guardian_decision_hash: [25u8; 32],
                guardian_counter: 26,
                guardian_trace_hash: [27u8; 32],
                guardian_measurement_root: [28u8; 32],
                guardian_checkpoint_root: [29u8; 32],
                verdict: ioi_types::app::AsymptoteObserverVerdict::Ok,
                veto_kind: None,
                evidence_hash: [30u8; 32],
            },
            guardian_certificate: sample_block_header()
                .guardian_certificate
                .expect("sample header must carry guardian certificate"),
        };
        let challenge = AsymptoteObserverChallenge {
            challenge_id: [31u8; 32],
            epoch: 9,
            height: 11,
            view: 4,
            kind: ioi_types::app::AsymptoteObserverChallengeKind::TranscriptMismatch,
            challenger_account_id: AccountId([32u8; 32]),
            assignment: Some(assignment.clone()),
            observation_request: Some(observation_request),
            transcript: Some(transcript.clone()),
            canonical_close: None,
            evidence_hash: [33u8; 32],
            details: "observer recovered a malformed request".to_string(),
        };
        let assignments_hash =
            canonical_asymptote_observer_assignments_hash(&[assignment]).expect("assignment hash");
        let transcripts_root = canonical_asymptote_observer_transcripts_hash(&[transcript.clone()])
            .expect("transcript root");
        let challenges_root = canonical_asymptote_observer_challenges_hash(&[challenge.clone()])
            .expect("challenge root");
        let artifacts = CanonicalObserverPublicationArtifacts {
            transcripts: vec![transcript],
            challenges: vec![challenge],
            transcript_commitment: AsymptoteObserverTranscriptCommitment {
                epoch: 9,
                height: 11,
                view: 4,
                assignments_hash,
                transcripts_root,
                transcript_count: 1,
            },
            challenge_commitment: AsymptoteObserverChallengeCommitment {
                epoch: 9,
                height: 11,
                view: 4,
                challenges_root,
                challenge_count: 1,
            },
            canonical_close: None,
            canonical_abort: Some(AsymptoteObserverCanonicalAbort {
                epoch: 9,
                height: 11,
                view: 4,
                assignments_hash,
                transcripts_root,
                challenges_root,
                transcript_count: 1,
                challenge_count: 1,
                challenge_cutoff_timestamp_ms: 1_700_000_000_500,
            }),
        };
        let (consensus_kick_tx, mut consensus_kick_rx) = mpsc::unbounded_channel();
        let publisher = GuardianRegistryPublisher {
            workload_client: Arc::new(TestWorkloadClient),
            tx_pool: Arc::new(Mempool::new()),
            consensus_kick_tx,
            nonce_manager: Arc::new(Mutex::new(BTreeMap::new())),
            local_keypair: libp2p::identity::Keypair::generate_ed25519(),
            chain_id: ChainId(1),
        };

        publish_canonical_observer_artifacts(&publisher, &artifacts)
            .await
            .expect("artifact publication should succeed");

        let selected = publisher.tx_pool.select_transactions(8);
        assert_eq!(selected.len(), 5);

        let mut published_bundle = None;
        let methods = selected
            .into_iter()
            .map(|tx| match tx {
                ChainTransaction::System(system_tx) => match system_tx.payload {
                    SystemPayload::CallService {
                        service_id,
                        method,
                        params,
                    } => {
                        assert_eq!(service_id, "guardian_registry");
                        if method == "publish_aft_canonical_order_artifact_bundle@v1" {
                            published_bundle = Some(
                                codec::from_bytes_canonical::<CanonicalOrderPublicationBundle>(
                                    &params,
                                )
                                .expect("decode published canonical-order bundle"),
                            );
                        }
                        method
                    }
                },
                other => panic!("unexpected non-system publication tx: {other:?}"),
            })
            .collect::<Vec<_>>();

        assert_eq!(
            methods,
            vec![
                "publish_asymptote_observer_transcript@v1".to_string(),
                "publish_asymptote_observer_transcript_commitment@v1".to_string(),
                "report_asymptote_observer_challenge@v1".to_string(),
                "publish_asymptote_observer_challenge_commitment@v1".to_string(),
                "publish_asymptote_observer_canonical_abort@v1".to_string(),
            ]
        );

        for _ in 0..5 {
            consensus_kick_rx
                .try_recv()
                .expect("publication should kick consensus for each enqueued tx");
        }
        assert!(
            consensus_kick_rx.try_recv().is_err(),
            "expected exactly one kick per published artifact tx"
        );
    }

    #[tokio::test]
    async fn publish_canonical_order_artifacts_enqueues_bulletin_surface_and_certificate() {
        let base_header = sample_block_header();
        let tx_one = ChainTransaction::System(Box::new(SystemTransaction {
            header: SignHeader {
                account_id: AccountId([41u8; 32]),
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
                account_id: AccountId([42u8; 32]),
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
            ioi_types::app::canonicalize_transactions_for_header(&base_header, &[tx_one, tx_two])
                .expect("canonicalized transactions");
        let tx_hashes: Vec<[u8; 32]> = ordered_transactions
            .iter()
            .map(|tx| tx.hash().expect("tx hash"))
            .collect();

        let mut header = base_header;
        header.transactions_root =
            ioi_types::app::canonical_transaction_root_from_hashes(&tx_hashes)
                .expect("transactions root");
        header.canonical_order_certificate = Some(
            build_committed_surface_canonical_order_certificate(&header, &ordered_transactions)
                .expect("build committed-surface certificate"),
        );

        let artifacts = build_canonical_order_publication_artifacts(&header, &ordered_transactions)
            .expect("build publication artifacts");
        let (consensus_kick_tx, mut consensus_kick_rx) = mpsc::unbounded_channel();
        let publisher = GuardianRegistryPublisher {
            workload_client: Arc::new(TestWorkloadClient),
            tx_pool: Arc::new(Mempool::new()),
            consensus_kick_tx,
            nonce_manager: Arc::new(Mutex::new(BTreeMap::new())),
            local_keypair: libp2p::identity::Keypair::generate_ed25519(),
            chain_id: ChainId(1),
        };

        publish_canonical_order_artifacts(&publisher, &artifacts)
            .await
            .expect("artifact publication should succeed");

        let selected = publisher.tx_pool.select_transactions(8);
        assert_eq!(selected.len(), 1);

        let mut published_bundle = None;
        let methods = selected
            .into_iter()
            .map(|tx| match tx {
                ChainTransaction::System(system_tx) => match system_tx.payload {
                    SystemPayload::CallService {
                        service_id,
                        method,
                        params,
                    } => {
                        assert_eq!(service_id, "guardian_registry");
                        if method == "publish_aft_canonical_order_artifact_bundle@v1" {
                            published_bundle = Some(
                                codec::from_bytes_canonical::<CanonicalOrderPublicationBundle>(
                                    &params,
                                )
                                .expect("decode published canonical-order bundle"),
                            );
                        }
                        method
                    }
                },
                other => panic!("unexpected non-system publication tx: {other:?}"),
            })
            .collect::<Vec<_>>();

        assert_eq!(
            methods,
            vec!["publish_aft_canonical_order_artifact_bundle@v1".to_string()]
        );
        let published_bundle = published_bundle.expect("published bundle captured");
        assert_eq!(
            published_bundle
                .bulletin_retrievability_profile
                .bulletin_commitment_hash,
            published_bundle
                .bulletin_availability_certificate
                .bulletin_commitment_hash
        );
        assert_eq!(
            published_bundle.bulletin_shard_manifest.entry_count,
            published_bundle.bulletin_commitment.entry_count
        );
        assert_eq!(
            published_bundle.bulletin_custody_receipt.bulletin_shard_manifest_hash,
            ioi_types::app::canonical_bulletin_shard_manifest_hash(
                &published_bundle.bulletin_shard_manifest,
            )
            .expect("hash published shard manifest")
        );

        for _ in 0..1 {
            consensus_kick_rx
                .try_recv()
                .expect("publication should kick consensus for each enqueued tx");
        }
        assert!(
            consensus_kick_rx.try_recv().is_err(),
            "expected exactly one kick per published artifact tx"
        );
    }

    #[tokio::test]
    async fn publish_canonical_order_abort_enqueues_abort_tx() {
        let header = sample_block_header();
        let artifacts = build_canonical_order_publication_artifacts(&header, &[])
            .expect("build publication artifacts");
        assert!(artifacts.bundle.is_none());
        let abort = artifacts
            .canonical_abort
            .as_ref()
            .expect("missing certificate must derive ordering abort");
        assert_eq!(abort.height, header.height);

        let (consensus_kick_tx, mut consensus_kick_rx) = mpsc::unbounded_channel();
        let publisher = GuardianRegistryPublisher {
            workload_client: Arc::new(TestWorkloadClient),
            tx_pool: Arc::new(Mempool::new()),
            consensus_kick_tx,
            nonce_manager: Arc::new(Mutex::new(BTreeMap::new())),
            local_keypair: libp2p::identity::Keypair::generate_ed25519(),
            chain_id: ChainId(1),
        };

        publish_canonical_order_artifacts(&publisher, &artifacts)
            .await
            .expect("abort publication should succeed");

        let selected = publisher.tx_pool.select_transactions(8);
        assert_eq!(selected.len(), 1);

        let methods = selected
            .into_iter()
            .map(|tx| match tx {
                ChainTransaction::System(system_tx) => match system_tx.payload {
                    SystemPayload::CallService {
                        service_id, method, ..
                    } => {
                        assert_eq!(service_id, "guardian_registry");
                        method
                    }
                },
                other => panic!("unexpected non-system publication tx: {other:?}"),
            })
            .collect::<Vec<_>>();

        assert_eq!(
            methods,
            vec!["publish_aft_canonical_order_abort@v1".to_string()]
        );
        consensus_kick_rx
            .try_recv()
            .expect("abort publication should kick consensus");
        assert!(
            consensus_kick_rx.try_recv().is_err(),
            "expected exactly one kick for the ordering abort publication"
        );
    }

    #[tokio::test]
    async fn publish_experimental_recovery_artifacts_enqueues_capsule_then_witness_certificate_when_capsule_is_missing(
    ) {
        let (block, scaffold) = sample_block_with_recovery_scaffold();
        let expected_receipt = build_experimental_recovery_scaffold_share_receipt(
            &block.header,
            &derive_recovery_witness_certificate_for_header(
                &block.header,
                block
                    .header
                    .guardian_certificate
                    .as_ref()
                    .expect("guardian certificate"),
            )
            .expect("derive recovery witness certificate")
            .expect("recovery witness certificate"),
        )
        .expect("build recovery receipt");
        let (consensus_kick_tx, mut consensus_kick_rx) = mpsc::unbounded_channel();
        let publisher = GuardianRegistryPublisher {
            workload_client: Arc::new(StaticStateWorkloadClient::default()),
            tx_pool: Arc::new(Mempool::new()),
            consensus_kick_tx,
            nonce_manager: Arc::new(Mutex::new(BTreeMap::new())),
            local_keypair: libp2p::identity::Keypair::generate_ed25519(),
            chain_id: ChainId(1),
        };

        publish_experimental_recovery_artifacts(&publisher, &block)
            .await
            .expect("recovery publication should succeed");

        let selected = publisher.tx_pool.select_transactions(8);
        assert_eq!(selected.len(), 3);

        let mut methods = Vec::new();
        let mut published_receipt = None;
        for tx in selected {
            match tx {
                ChainTransaction::System(system_tx) => match system_tx.payload {
                    SystemPayload::CallService {
                        service_id,
                        method,
                        params,
                    } => {
                        assert_eq!(service_id, "guardian_registry");
                        if method == "publish_aft_recovery_share_receipt@v1" {
                            published_receipt = Some(
                                codec::from_bytes_canonical::<RecoveryShareReceipt>(&params)
                                    .expect("decode recovery share receipt"),
                            );
                        }
                        methods.push(method);
                    }
                },
                other => panic!("unexpected non-system publication tx: {other:?}"),
            }
        }

        assert_eq!(
            methods,
            vec![
                "publish_aft_recovery_capsule@v1".to_string(),
                "publish_aft_recovery_witness_certificate@v1".to_string(),
                "publish_aft_recovery_share_receipt@v1".to_string(),
            ]
        );
        assert_eq!(published_receipt, Some(expected_receipt));
        for _ in 0..3 {
            consensus_kick_rx
                .try_recv()
                .expect("recovery publication should kick consensus");
        }
        assert!(consensus_kick_rx.try_recv().is_err());
        assert_eq!(scaffold.capsule.coding.recovery_threshold, 1);
    }

    #[tokio::test]
    async fn publish_experimental_recovery_artifacts_enqueues_only_witness_certificate_and_receipt_when_capsule_matches(
    ) {
        let (block, scaffold) = sample_block_with_recovery_scaffold();
        let expected_receipt = build_experimental_recovery_scaffold_share_receipt(
            &block.header,
            &derive_recovery_witness_certificate_for_header(
                &block.header,
                block
                    .header
                    .guardian_certificate
                    .as_ref()
                    .expect("guardian certificate"),
            )
            .expect("derive recovery witness certificate")
            .expect("recovery witness certificate"),
        )
        .expect("build recovery receipt");
        let mut raw_state = BTreeMap::new();
        raw_state.insert(
            aft_recovery_capsule_key(block.header.height),
            codec::to_bytes_canonical(&scaffold.capsule).expect("encode recovery capsule"),
        );
        let (consensus_kick_tx, mut consensus_kick_rx) = mpsc::unbounded_channel();
        let publisher = GuardianRegistryPublisher {
            workload_client: Arc::new(StaticStateWorkloadClient { raw_state }),
            tx_pool: Arc::new(Mempool::new()),
            consensus_kick_tx,
            nonce_manager: Arc::new(Mutex::new(BTreeMap::new())),
            local_keypair: libp2p::identity::Keypair::generate_ed25519(),
            chain_id: ChainId(1),
        };

        publish_experimental_recovery_artifacts(&publisher, &block)
            .await
            .expect("recovery publication should succeed");

        let selected = publisher.tx_pool.select_transactions(8);
        assert_eq!(selected.len(), 2);

        let mut methods = Vec::new();
        let mut published_receipt = None;
        for tx in selected {
            match tx {
                ChainTransaction::System(system_tx) => match system_tx.payload {
                    SystemPayload::CallService {
                        service_id,
                        method,
                        params,
                    } => {
                        assert_eq!(service_id, "guardian_registry");
                        if method == "publish_aft_recovery_share_receipt@v1" {
                            published_receipt = Some(
                                codec::from_bytes_canonical::<RecoveryShareReceipt>(&params)
                                    .expect("decode recovery share receipt"),
                            );
                        }
                        methods.push(method);
                    }
                },
                other => panic!("unexpected non-system publication tx: {other:?}"),
            }
        }

        assert_eq!(
            methods,
            vec![
                "publish_aft_recovery_witness_certificate@v1".to_string(),
                "publish_aft_recovery_share_receipt@v1".to_string(),
            ]
        );
        assert_eq!(published_receipt, Some(expected_receipt));
        for _ in 0..2 {
            consensus_kick_rx
                .try_recv()
                .expect("recovery publication should kick consensus");
        }
        assert!(consensus_kick_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn publish_experimental_recovery_artifacts_skips_receipt_when_missing_share_exists() {
        let (block, scaffold) = sample_block_with_recovery_scaffold();
        let mut raw_state = BTreeMap::new();
        raw_state.insert(
            aft_recovery_capsule_key(block.header.height),
            codec::to_bytes_canonical(&scaffold.capsule).expect("encode recovery capsule"),
        );
        raw_state.insert(
            aft_missing_recovery_share_key(block.header.height, &[0x41u8; 32]),
            codec::to_bytes_canonical(&ioi_types::app::MissingRecoveryShare {
                height: block.header.height,
                witness_manifest_hash: [0x41u8; 32],
                recovery_capsule_hash: scaffold
                    .recovery_binding()
                    .expect("recovery binding")
                    .recovery_capsule_hash,
                recovery_window_close_ms: scaffold.capsule.recovery_window_close_ms,
            })
            .expect("encode missing share"),
        );
        let (consensus_kick_tx, mut consensus_kick_rx) = mpsc::unbounded_channel();
        let publisher = GuardianRegistryPublisher {
            workload_client: Arc::new(StaticStateWorkloadClient { raw_state }),
            tx_pool: Arc::new(Mempool::new()),
            consensus_kick_tx,
            nonce_manager: Arc::new(Mutex::new(BTreeMap::new())),
            local_keypair: libp2p::identity::Keypair::generate_ed25519(),
            chain_id: ChainId(1),
        };

        publish_experimental_recovery_artifacts(&publisher, &block)
            .await
            .expect("recovery publication should succeed");

        let methods = publisher
            .tx_pool
            .select_transactions(8)
            .into_iter()
            .map(|tx| match tx {
                ChainTransaction::System(system_tx) => match system_tx.payload {
                    SystemPayload::CallService {
                        service_id, method, ..
                    } => {
                        assert_eq!(service_id, "guardian_registry");
                        method
                    }
                },
                other => panic!("unexpected non-system publication tx: {other:?}"),
            })
            .collect::<Vec<_>>();

        assert_eq!(
            methods,
            vec!["publish_aft_recovery_witness_certificate@v1".to_string()]
        );
        consensus_kick_rx
            .try_recv()
            .expect("recovery publication should kick consensus");
        assert!(consensus_kick_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn publish_experimental_recovery_artifacts_enqueues_only_witness_certificate_when_capsule_matches(
    ) {
        let (block, scaffold) = sample_block_with_recovery_scaffold();
        let mut raw_state = BTreeMap::new();
        raw_state.insert(
            aft_recovery_capsule_key(block.header.height),
            codec::to_bytes_canonical(&scaffold.capsule).expect("encode recovery capsule"),
        );
        raw_state.insert(
            aft_recovery_share_receipt_key(
                block.header.height,
                &[0x41u8; 32],
                &canonical_block_commitment_hash(&block.header).expect("block commitment"),
            ),
            codec::to_bytes_canonical(
                &build_experimental_recovery_scaffold_share_receipt(
                    &block.header,
                    &derive_recovery_witness_certificate_for_header(
                        &block.header,
                        block
                            .header
                            .guardian_certificate
                            .as_ref()
                            .expect("guardian certificate"),
                    )
                    .expect("derive recovery witness certificate")
                    .expect("recovery witness certificate"),
                )
                .expect("build recovery receipt"),
            )
            .expect("encode recovery receipt"),
        );
        let (consensus_kick_tx, mut consensus_kick_rx) = mpsc::unbounded_channel();
        let publisher = GuardianRegistryPublisher {
            workload_client: Arc::new(StaticStateWorkloadClient { raw_state }),
            tx_pool: Arc::new(Mempool::new()),
            consensus_kick_tx,
            nonce_manager: Arc::new(Mutex::new(BTreeMap::new())),
            local_keypair: libp2p::identity::Keypair::generate_ed25519(),
            chain_id: ChainId(1),
        };

        publish_experimental_recovery_artifacts(&publisher, &block)
            .await
            .expect("recovery publication should succeed");

        let selected = publisher.tx_pool.select_transactions(8);
        assert_eq!(selected.len(), 1);

        let methods = selected
            .into_iter()
            .map(|tx| match tx {
                ChainTransaction::System(system_tx) => match system_tx.payload {
                    SystemPayload::CallService {
                        service_id, method, ..
                    } => {
                        assert_eq!(service_id, "guardian_registry");
                        method
                    }
                },
                other => panic!("unexpected non-system publication tx: {other:?}"),
            })
            .collect::<Vec<_>>();

        assert_eq!(
            methods,
            vec!["publish_aft_recovery_witness_certificate@v1".to_string()]
        );
        consensus_kick_rx
            .try_recv()
            .expect("recovery publication should kick consensus");
        assert!(consensus_kick_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn publish_experimental_recovery_artifacts_skips_when_capsule_is_mismatched() {
        let (block, scaffold) = sample_block_with_recovery_scaffold();
        let mismatched_capsule = RecoveryCapsule {
            payload_commitment_hash: [0x55u8; 32],
            ..scaffold.capsule
        };
        let mut raw_state = BTreeMap::new();
        raw_state.insert(
            aft_recovery_capsule_key(block.header.height),
            codec::to_bytes_canonical(&mismatched_capsule).expect("encode recovery capsule"),
        );
        let (consensus_kick_tx, mut consensus_kick_rx) = mpsc::unbounded_channel();
        let publisher = GuardianRegistryPublisher {
            workload_client: Arc::new(StaticStateWorkloadClient { raw_state }),
            tx_pool: Arc::new(Mempool::new()),
            consensus_kick_tx,
            nonce_manager: Arc::new(Mutex::new(BTreeMap::new())),
            local_keypair: libp2p::identity::Keypair::generate_ed25519(),
            chain_id: ChainId(1),
        };

        publish_experimental_recovery_artifacts(&publisher, &block)
            .await
            .expect("mismatched capsule should be skipped, not rejected");

        assert!(
            publisher.tx_pool.select_transactions(8).is_empty(),
            "no publication tx should be enqueued when the published capsule mismatches the signed binding"
        );
        assert!(
            consensus_kick_rx.try_recv().is_err(),
            "skipped recovery publication should not kick consensus"
        );
    }

    #[tokio::test]
    async fn publish_experimental_sealed_recovery_artifacts_enqueues_capsule_witness_certificates_and_receipts(
    ) {
        let (block, capsule, binding_assignments) = sample_block_with_sealed_recovery_bindings();
        let expected_witnesses = binding_assignments
            .iter()
            .map(|assignment| assignment.witness_manifest_hash)
            .collect::<std::collections::BTreeSet<_>>();
        let expected_receipts = block
            .header
            .sealed_finality_proof
            .as_ref()
            .expect("sealed finality proof")
            .witness_certificates
            .iter()
            .map(|witness_certificate| {
                let statement =
                    ioi_types::app::guardian_witness_statement_for_header_with_recovery_binding(
                        &block.header,
                        block
                            .header
                            .guardian_certificate
                            .as_ref()
                            .expect("guardian certificate"),
                        witness_certificate.recovery_binding.clone(),
                    );
                let certificate = ioi_types::app::derive_recovery_witness_certificate(
                    &statement,
                    witness_certificate,
                )
                .expect("derive sealed recovery witness certificate")
                .expect("recovery witness certificate");
                build_recovery_share_receipt_for_header(&block.header, &certificate)
                    .expect("build recovery share receipt")
            })
            .collect::<Vec<_>>();
        let (consensus_kick_tx, mut consensus_kick_rx) = mpsc::unbounded_channel();
        let publisher = GuardianRegistryPublisher {
            workload_client: Arc::new(StaticStateWorkloadClient::default()),
            tx_pool: Arc::new(Mempool::new()),
            consensus_kick_tx,
            nonce_manager: Arc::new(Mutex::new(BTreeMap::new())),
            local_keypair: libp2p::identity::Keypair::generate_ed25519(),
            chain_id: ChainId(1),
        };

        publish_experimental_sealed_recovery_artifacts(
            &publisher,
            &block,
            Some(&capsule),
            &binding_assignments,
        )
        .await
        .expect("sealed recovery publication should succeed");

        let selected = publisher.tx_pool.select_transactions(16);
        assert_eq!(
            selected.len(),
            1 + 2 * usize::from(sample_parity_family_share_count())
        );

        let mut methods = Vec::new();
        let mut published_receipts = Vec::new();
        let mut published_witnesses = std::collections::BTreeSet::new();
        for tx in selected {
            match tx {
                ChainTransaction::System(system_tx) => match system_tx.payload {
                    SystemPayload::CallService {
                        service_id,
                        method,
                        params,
                    } => {
                        assert_eq!(service_id, "guardian_registry");
                        if method == "publish_aft_recovery_witness_certificate@v1" {
                            let certificate = codec::from_bytes_canonical::<
                                ioi_types::app::RecoveryWitnessCertificate,
                            >(&params)
                            .expect("decode recovery witness certificate");
                            published_witnesses.insert(certificate.witness_manifest_hash);
                        }
                        if method == "publish_aft_recovery_share_receipt@v1" {
                            published_receipts.push(
                                codec::from_bytes_canonical::<RecoveryShareReceipt>(&params)
                                    .expect("decode recovery share receipt"),
                            );
                        }
                        methods.push(method);
                    }
                },
                other => panic!("unexpected non-system publication tx: {other:?}"),
            }
        }

        assert_eq!(
            methods,
            vec![
                "publish_aft_recovery_capsule@v1".to_string(),
                "publish_aft_recovery_witness_certificate@v1".to_string(),
                "publish_aft_recovery_share_receipt@v1".to_string(),
                "publish_aft_recovery_witness_certificate@v1".to_string(),
                "publish_aft_recovery_share_receipt@v1".to_string(),
                "publish_aft_recovery_witness_certificate@v1".to_string(),
                "publish_aft_recovery_share_receipt@v1".to_string(),
                "publish_aft_recovery_witness_certificate@v1".to_string(),
                "publish_aft_recovery_share_receipt@v1".to_string(),
            ]
        );
        assert_eq!(published_witnesses, expected_witnesses);
        assert_eq!(published_receipts, expected_receipts);
        for _ in 0..(1 + 2 * usize::from(sample_parity_family_share_count())) {
            consensus_kick_rx
                .try_recv()
                .expect("sealed recovery publication should kick consensus");
        }
        assert!(consensus_kick_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn publish_experimental_sealed_recovery_artifacts_skips_when_a_witness_binding_is_tampered(
    ) {
        let (mut block, capsule, binding_assignments) =
            sample_block_with_sealed_recovery_bindings();
        block
            .header
            .sealed_finality_proof
            .as_mut()
            .expect("sealed finality proof")
            .witness_certificates[0]
            .recovery_binding
            .as_mut()
            .expect("recovery binding")
            .share_commitment_hash[0] ^= 0xff;
        let (consensus_kick_tx, mut consensus_kick_rx) = mpsc::unbounded_channel();
        let publisher = GuardianRegistryPublisher {
            workload_client: Arc::new(StaticStateWorkloadClient::default()),
            tx_pool: Arc::new(Mempool::new()),
            consensus_kick_tx,
            nonce_manager: Arc::new(Mutex::new(BTreeMap::new())),
            local_keypair: libp2p::identity::Keypair::generate_ed25519(),
            chain_id: ChainId(1),
        };

        publish_experimental_sealed_recovery_artifacts(
            &publisher,
            &block,
            Some(&capsule),
            &binding_assignments,
        )
        .await
        .expect("tampered sealed recovery publication should be skipped, not rejected");

        assert!(
            publisher.tx_pool.select_transactions(16).is_empty(),
            "no publication tx should be enqueued when one sealed witness binding is tampered"
        );
        assert!(
            consensus_kick_rx.try_recv().is_err(),
            "skipped sealed recovery publication should not kick consensus"
        );
    }

    #[tokio::test]
    async fn publish_experimental_locally_held_recovery_share_materials_enqueues_public_reveals_that_reconstruct_payload(
    ) {
        let (block, capsule, binding_assignments) = sample_block_with_sealed_recovery_bindings();
        let witness_seed = sample_guardian_witness_seed();
        let witness_set = sample_guardian_witness_set(vec![
            [0x91u8; 32],
            [0x92u8; 32],
            [0x93u8; 32],
            [0x94u8; 32],
        ]);
        let materials = build_experimental_multi_witness_recovery_share_materials(
            &block.header,
            &block.transactions,
            &witness_seed,
            &witness_set,
            0,
            sample_parity_family_share_count(),
            sample_parity_family_recovery_threshold(),
        )
        .expect("recovery share materials");
        let signer = MockRecoveryRevealSigner {
            materials: materials
                .iter()
                .cloned()
                .map(|material| {
                    (
                        (
                            material.witness_manifest_hash,
                            material.share_commitment_hash,
                        ),
                        material,
                    )
                })
                .collect(),
        };

        let mut raw_state = BTreeMap::new();
        raw_state.insert(
            aft_recovery_capsule_key(block.header.height),
            codec::to_bytes_canonical(&capsule).expect("encode recovery capsule"),
        );
        for witness_certificate in &block
            .header
            .sealed_finality_proof
            .as_ref()
            .expect("sealed finality proof")
            .witness_certificates
        {
            let statement =
                ioi_types::app::guardian_witness_statement_for_header_with_recovery_binding(
                    &block.header,
                    block
                        .header
                        .guardian_certificate
                        .as_ref()
                        .expect("guardian certificate"),
                    witness_certificate.recovery_binding.clone(),
                );
            let certificate = ioi_types::app::derive_recovery_witness_certificate(
                &statement,
                witness_certificate,
            )
            .expect("derive recovery witness certificate")
            .expect("recovery witness certificate");
            let receipt = build_recovery_share_receipt_for_header(&block.header, &certificate)
                .expect("recovery share receipt");
            raw_state.insert(
                ioi_types::app::aft_recovery_witness_certificate_key(
                    certificate.height,
                    &certificate.witness_manifest_hash,
                ),
                codec::to_bytes_canonical(&certificate).expect("encode recovery witness"),
            );
            raw_state.insert(
                aft_recovery_share_receipt_key(
                    receipt.height,
                    &receipt.witness_manifest_hash,
                    &receipt.block_commitment_hash,
                ),
                codec::to_bytes_canonical(&receipt).expect("encode recovery share receipt"),
            );
        }

        let (consensus_kick_tx, mut consensus_kick_rx) = mpsc::unbounded_channel();
        let publisher = GuardianRegistryPublisher {
            workload_client: Arc::new(StaticStateWorkloadClient { raw_state }),
            tx_pool: Arc::new(Mempool::new()),
            consensus_kick_tx,
            nonce_manager: Arc::new(Mutex::new(BTreeMap::new())),
            local_keypair: libp2p::identity::Keypair::generate_ed25519(),
            chain_id: ChainId(1),
        };

        let loaded_materials = publish_experimental_locally_held_recovery_share_materials(
            &publisher,
            &signer,
            &block,
            &witness_seed,
            &witness_set,
            0,
            &binding_assignments,
        )
        .await
        .expect("recovery share material publication should succeed");
        assert_eq!(loaded_materials, materials);

        let selected = publisher.tx_pool.select_transactions(16);
        assert_eq!(
            selected.len(),
            usize::from(sample_parity_family_share_count())
        );

        let mut methods = Vec::new();
        let mut published_materials = Vec::new();
        for tx in selected {
            match tx {
                ChainTransaction::System(system_tx) => match system_tx.payload {
                    SystemPayload::CallService {
                        service_id,
                        method,
                        params,
                    } => {
                        assert_eq!(service_id, "guardian_registry");
                        if method == "publish_aft_recovery_share_material@v1" {
                            published_materials.push(
                                codec::from_bytes_canonical::<RecoveryShareMaterial>(&params)
                                    .expect("decode recovery share material"),
                            );
                        }
                        methods.push(method);
                    }
                },
                other => panic!("unexpected non-system publication tx: {other:?}"),
            }
        }

        assert_eq!(
            methods,
            vec![
                "publish_aft_recovery_share_material@v1".to_string(),
                "publish_aft_recovery_share_material@v1".to_string(),
                "publish_aft_recovery_share_material@v1".to_string(),
                "publish_aft_recovery_share_material@v1".to_string(),
            ]
        );
        assert_eq!(published_materials, materials);

        let reconstructed =
            recover_recoverable_slot_payload_v3_from_share_materials(&published_materials[..3])
                .expect(
                    "payload should reconstruct from three published parity-family share reveals",
                );
        let expected_certificate =
            build_committed_surface_canonical_order_certificate(&block.header, &block.transactions)
                .expect("canonical order certificate");
        let expected_payload = build_recoverable_slot_payload_v3(
            &block.header,
            &block.transactions,
            &expected_certificate,
        )
        .expect("recoverable slot payload");
        assert_eq!(reconstructed, expected_payload);

        for _ in 0..usize::from(sample_parity_family_share_count()) {
            consensus_kick_rx
                .try_recv()
                .expect("share-material publication should kick consensus");
        }
        assert!(consensus_kick_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn publish_experimental_recovery_pipeline_enqueues_recovered_publication_bundle_after_receipts_and_reveals(
    ) {
        let (block, capsule, binding_assignments) = sample_block_with_sealed_recovery_bindings();
        let previous_canonical_collapse =
            sample_previous_canonical_collapse_object(block.header.height - 1, 0x74);
        let witness_seed = sample_guardian_witness_seed();
        let witness_set = sample_guardian_witness_set(vec![
            [0x91u8; 32],
            [0x92u8; 32],
            [0x93u8; 32],
            [0x94u8; 32],
        ]);
        let materials = build_experimental_multi_witness_recovery_share_materials(
            &block.header,
            &block.transactions,
            &witness_seed,
            &witness_set,
            0,
            sample_parity_family_share_count(),
            sample_parity_family_recovery_threshold(),
        )
        .expect("recovery share materials");
        let signer = MockRecoveryRevealSigner {
            materials: materials
                .iter()
                .cloned()
                .map(|material| {
                    (
                        (
                            material.witness_manifest_hash,
                            material.share_commitment_hash,
                        ),
                        material,
                    )
                })
                .collect(),
        };

        let synthetic_recovered =
            build_recovered_publication_bundle(&materials).expect("synthetic recovered bundle");
        let (segment_start_height, segment_end_height) = archived_recovered_restart_page_range(
            synthetic_recovered.height,
            AFT_RECOVERED_CONSENSUS_HEADER_WINDOW,
            AFT_RECOVERED_CONSENSUS_HEADER_STITCH_OVERLAP,
            recovered_consensus_header_stitch_window_budget(),
            recovered_consensus_header_stitch_segment_budget(),
        )
        .expect("current archived page range");
        let (previous_start_height, previous_end_height) = archived_recovered_restart_page_range(
            segment_end_height - 1,
            AFT_RECOVERED_CONSENSUS_HEADER_WINDOW,
            AFT_RECOVERED_CONSENSUS_HEADER_STITCH_OVERLAP,
            recovered_consensus_header_stitch_window_budget(),
            recovered_consensus_header_stitch_segment_budget(),
        )
        .expect("previous archived page range");
        let archived_profile = default_archived_recovered_history_profile()
            .expect("default archived recovered-history profile");
        let archived_activation =
            build_archived_recovered_history_profile_activation(&archived_profile, None, 1, None)
                .expect("default archived recovered-history profile activation");
        let mut raw_state = BTreeMap::new();
        let synthetic_start_height = previous_start_height.min(segment_start_height);
        let synthetic_bundles = (synthetic_start_height..segment_end_height)
            .map(|height| {
                (
                    height,
                    synthetic_recovered_publication_bundle_for_height(&synthetic_recovered, height),
                )
            })
            .collect::<BTreeMap<_, _>>();
        for bundle in synthetic_bundles.values() {
            let recovered_key = aft_recovered_publication_bundle_key(
                bundle.height,
                &bundle.block_commitment_hash,
                &bundle.supporting_witness_manifest_hashes,
            )
            .expect("recovered publication bundle key");
            raw_state.insert(
                recovered_key,
                codec::to_bytes_canonical(bundle).expect("encode recovered publication bundle"),
            );
        }
        let previous_segment_bundles = (previous_start_height..=previous_end_height)
            .map(|height| {
                synthetic_bundles
                    .get(&height)
                    .cloned()
                    .expect("synthetic previous-segment recovered bundle")
            })
            .collect::<Vec<_>>();
        let previous_segment = build_archived_recovered_history_segment(
            &previous_segment_bundles,
            None,
            None,
            &archived_profile,
            &archived_activation,
        )
        .expect("previous archived recovered-history segment");
        let previous_page = synthetic_archived_restart_page(
            &previous_segment,
            synthetic_recovered.parent_block_commitment_hash,
        );
        let previous_checkpoint =
            build_archived_recovered_history_checkpoint(&previous_segment, &previous_page, None)
                .expect("previous archived recovered-history checkpoint");
        let active_validator_sets = validator_sets(&[(18, 1), (145, 1), (19, 1)]);
        let active_validator_set_bytes =
            write_validator_sets(&active_validator_sets).expect("encode active validator sets");
        let persisted_active_validator_sets = read_validator_sets(&active_validator_set_bytes)
            .expect("decode persisted active validator sets");
        raw_state.insert(
            aft_archived_recovered_history_segment_key(
                previous_segment.start_height,
                previous_segment.end_height,
            ),
            codec::to_bytes_canonical(&previous_segment)
                .expect("encode previous archived recovered-history segment"),
        );
        raw_state.insert(
            aft_archived_recovered_restart_page_key(&previous_page.segment_hash),
            codec::to_bytes_canonical(&previous_page)
                .expect("encode previous archived recovered restart page"),
        );
        raw_state.insert(
            aft_archived_recovered_history_checkpoint_key(
                previous_checkpoint.covered_start_height,
                previous_checkpoint.covered_end_height,
            ),
            codec::to_bytes_canonical(&previous_checkpoint)
                .expect("encode previous archived recovered-history checkpoint"),
        );
        raw_state.insert(
            ioi_types::app::AFT_LATEST_ARCHIVED_RECOVERED_HISTORY_CHECKPOINT_KEY.to_vec(),
            codec::to_bytes_canonical(&previous_checkpoint)
                .expect("encode latest archived recovered-history checkpoint"),
        );
        raw_state.insert(VALIDATOR_SET_KEY.to_vec(), active_validator_set_bytes);

        let (consensus_kick_tx, mut consensus_kick_rx) = mpsc::unbounded_channel();
        let publisher = GuardianRegistryPublisher {
            workload_client: Arc::new(StaticStateWorkloadClient { raw_state }),
            tx_pool: Arc::new(Mempool::new()),
            consensus_kick_tx,
            nonce_manager: Arc::new(Mutex::new(BTreeMap::new())),
            local_keypair: libp2p::identity::Keypair::generate_ed25519(),
            chain_id: ChainId(1),
        };

        publish_experimental_sealed_recovery_artifacts(
            &publisher,
            &block,
            Some(&capsule),
            &binding_assignments,
        )
        .await
        .expect("sealed recovery artifacts should publish");
        let published_materials = publish_experimental_locally_held_recovery_share_materials(
            &publisher,
            &signer,
            &block,
            &witness_seed,
            &witness_set,
            0,
            &binding_assignments,
        )
        .await
        .expect("share material publication should succeed");
        let recovered =
            publish_experimental_recovered_publication_bundle(&publisher, &published_materials)
                .await
                .expect("recovered publication bundle should publish")
                .expect("recovered publication bundle object");
        let (archived_profile, archived_activation) =
            ensure_archived_recovered_history_profile(&publisher)
                .await
                .expect("archived recovered-history profile should publish");
        let archived_segment = publish_archived_recovered_history_segment(
            &publisher,
            &recovered,
            &archived_profile,
            &archived_activation,
        )
        .await
        .expect("archived recovered-history segment should publish")
        .expect("archived recovered-history segment object");
        let support_materials =
            supporting_recovery_materials_for_recovered_bundle(&recovered, &published_materials)
                .expect("supporting recovery materials");
        let (recovered_full_surface, _, recovered_close, _) =
            recover_full_canonical_order_surface_from_share_materials(&support_materials)
                .expect("recover full canonical order surface");
        let canonical_collapse_object =
            ioi_types::app::derive_canonical_collapse_object_from_recovered_surface(
                &recovered_full_surface,
                &recovered_close,
                Some(&previous_canonical_collapse),
            )
            .expect("canonical collapse object from recovered surface");
        let archived_page = publish_archived_recovered_restart_page(
            &publisher,
            &archived_segment,
            &canonical_collapse_object,
            &recovered,
            &published_materials,
        )
        .await
        .expect("archived recovered restart page should publish")
        .expect("archived recovered restart page object");
        let archived_checkpoint = publish_archived_recovered_history_checkpoint(
            &publisher,
            &archived_segment,
            &archived_page,
        )
        .await
        .expect("archived recovered-history checkpoint should publish")
        .expect("archived recovered-history checkpoint object");
        let archived_retention_receipt = publish_archived_recovered_history_retention_receipt(
            &publisher,
            &archived_checkpoint,
            &archived_profile,
        )
        .await
        .expect("archived recovered-history retention receipt should publish")
        .expect("archived recovered-history retention receipt object");

        let selected = publisher.tx_pool.select_transactions(48);
        assert_eq!(
            selected.len(),
            3 * usize::from(sample_parity_family_share_count()) + 8
        );

        let mut methods = Vec::new();
        let mut published_recovered = None;
        let mut published_archived_profile = None;
        let mut published_archived_profile_activation = None;
        let mut published_archived_segment = None;
        let mut published_archived_page = None;
        let mut published_archived_checkpoint = None;
        let mut published_archived_retention_receipt = None;
        for tx in selected {
            match tx {
                ChainTransaction::System(system_tx) => match system_tx.payload {
                    SystemPayload::CallService {
                        service_id,
                        method,
                        params,
                    } => {
                        assert_eq!(service_id, "guardian_registry");
                        if method == "publish_aft_recovered_publication_bundle@v1" {
                            published_recovered = Some(
                                codec::from_bytes_canonical::<RecoveredPublicationBundle>(&params)
                                    .expect("decode recovered publication bundle"),
                            );
                        } else if method == "publish_aft_archived_recovered_history_profile@v1" {
                            published_archived_profile = Some(
                                codec::from_bytes_canonical::<ArchivedRecoveredHistoryProfile>(
                                    &params,
                                )
                                .expect("decode archived recovered-history profile"),
                            );
                        } else if method
                            == "publish_aft_archived_recovered_history_profile_activation@v1"
                        {
                            published_archived_profile_activation = Some(
                                codec::from_bytes_canonical::<
                                    ArchivedRecoveredHistoryProfileActivation,
                                >(&params)
                                .expect("decode archived recovered-history profile activation"),
                            );
                        } else if method == "publish_aft_archived_recovered_history_segment@v1" {
                            published_archived_segment = Some(
                                codec::from_bytes_canonical::<ArchivedRecoveredHistorySegment>(
                                    &params,
                                )
                                .expect("decode archived recovered-history segment"),
                            );
                        } else if method == "publish_aft_archived_recovered_restart_page@v1" {
                            published_archived_page = Some(
                                codec::from_bytes_canonical::<ArchivedRecoveredRestartPage>(
                                    &params,
                                )
                                .expect("decode archived recovered restart page"),
                            );
                        } else if method == "publish_aft_archived_recovered_history_checkpoint@v1" {
                            published_archived_checkpoint = Some(
                                codec::from_bytes_canonical::<ArchivedRecoveredHistoryCheckpoint>(
                                    &params,
                                )
                                .expect("decode archived recovered-history checkpoint"),
                            );
                        } else if method
                            == "publish_aft_archived_recovered_history_retention_receipt@v1"
                        {
                            published_archived_retention_receipt = Some(
                                codec::from_bytes_canonical::<
                                    ArchivedRecoveredHistoryRetentionReceipt,
                                >(&params)
                                .expect("decode archived recovered-history retention receipt"),
                            );
                        }
                        methods.push(method);
                    }
                },
                other => panic!("unexpected non-system publication tx: {other:?}"),
            }
        }

        assert_eq!(
            methods,
            vec![
                "publish_aft_recovery_capsule@v1".to_string(),
                "publish_aft_recovery_witness_certificate@v1".to_string(),
                "publish_aft_recovery_share_receipt@v1".to_string(),
                "publish_aft_recovery_witness_certificate@v1".to_string(),
                "publish_aft_recovery_share_receipt@v1".to_string(),
                "publish_aft_recovery_witness_certificate@v1".to_string(),
                "publish_aft_recovery_share_receipt@v1".to_string(),
                "publish_aft_recovery_witness_certificate@v1".to_string(),
                "publish_aft_recovery_share_receipt@v1".to_string(),
                "publish_aft_recovery_share_material@v1".to_string(),
                "publish_aft_recovery_share_material@v1".to_string(),
                "publish_aft_recovery_share_material@v1".to_string(),
                "publish_aft_recovery_share_material@v1".to_string(),
                "publish_aft_recovered_publication_bundle@v1".to_string(),
                "publish_aft_archived_recovered_history_profile@v1".to_string(),
                "publish_aft_archived_recovered_history_profile_activation@v1".to_string(),
                "publish_aft_archived_recovered_history_segment@v1".to_string(),
                "publish_aft_archived_recovered_restart_page@v1".to_string(),
                "publish_aft_archived_recovered_history_checkpoint@v1".to_string(),
                "publish_aft_archived_recovered_history_retention_receipt@v1".to_string(),
            ]
        );
        assert_eq!(published_recovered, Some(recovered.clone()));
        assert_eq!(published_archived_profile, Some(archived_profile.clone()));
        assert_eq!(
            published_archived_profile_activation,
            Some(
                build_archived_recovered_history_profile_activation(
                    &archived_profile,
                    None,
                    1,
                    None,
                )
                .expect("expected archived recovered-history profile activation")
            )
        );
        assert_eq!(published_archived_segment, Some(archived_segment.clone()));
        assert_eq!(published_archived_page, Some(archived_page.clone()));
        assert_eq!(
            published_archived_checkpoint,
            Some(archived_checkpoint.clone())
        );
        assert_eq!(
            published_archived_retention_receipt,
            Some(archived_retention_receipt.clone())
        );
        assert_eq!(
            recovered,
            build_recovered_publication_bundle(&materials).expect("expected recovered bundle")
        );
        let expected_archived_bundles = (segment_start_height..=segment_end_height)
            .map(|height| {
                if height == recovered.height {
                    recovered.clone()
                } else {
                    synthetic_bundles
                        .get(&height)
                        .cloned()
                        .expect("synthetic archived recovered-history bundle")
                }
            })
            .collect::<Vec<_>>();
        let expected_overlap_range = Some((
            segment_start_height.max(previous_segment.start_height),
            segment_end_height
                .saturating_sub(1)
                .min(previous_segment.end_height),
        ));
        assert_eq!(
            archived_segment,
            build_archived_recovered_history_segment(
                &expected_archived_bundles,
                Some(&previous_segment),
                expected_overlap_range,
                &archived_profile,
                &archived_activation,
            )
            .expect("expected archived recovered-history segment")
        );
        let expected_archived_page = build_archived_recovered_restart_page(
            &archived_segment,
            &[
                previous_page.restart_headers[usize::try_from(
                    segment_start_height - previous_start_height,
                )
                .expect("overlap page offset")..]
                    .to_vec(),
                vec![archived_page
                    .restart_headers
                    .last()
                    .cloned()
                    .expect("published archived restart page tip")],
            ]
            .concat(),
        )
        .expect("expected archived recovered restart page");
        assert_eq!(archived_page, expected_archived_page);
        let expected_archived_checkpoint = build_archived_recovered_history_checkpoint(
            &archived_segment,
            &archived_page,
            Some(&previous_checkpoint),
        )
        .expect("expected archived recovered-history checkpoint");
        assert_eq!(archived_checkpoint, expected_archived_checkpoint);
        let expected_archived_retention_receipt =
            build_archived_recovered_history_retention_receipt(
                &archived_checkpoint,
                canonical_validator_sets_hash(&persisted_active_validator_sets)
                    .expect("validator set commitment hash"),
                archived_recovered_history_retained_through_height(
                    &archived_checkpoint,
                    &archived_profile,
                )
                .expect("retained-through height from archived profile"),
            )
            .expect("expected archived recovered-history retention receipt");
        assert_eq!(
            archived_retention_receipt,
            expected_archived_retention_receipt
        );

        for _ in 0..(3 * usize::from(sample_parity_family_share_count()) + 8) {
            consensus_kick_rx
                .try_recv()
                .expect("publication should kick consensus for each enqueued tx");
        }
        assert!(consensus_kick_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn publish_canonical_collapse_object_enqueues_collapse_tx() {
        let base_header = sample_block_header();
        let tx_one = ChainTransaction::System(Box::new(SystemTransaction {
            header: SignHeader {
                account_id: AccountId([51u8; 32]),
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
                account_id: AccountId([52u8; 32]),
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
            ioi_types::app::canonicalize_transactions_for_header(&base_header, &[tx_one, tx_two])
                .expect("canonicalized transactions");
        let tx_hashes: Vec<[u8; 32]> = ordered_transactions
            .iter()
            .map(|tx| tx.hash().expect("tx hash"))
            .collect();

        let mut header = base_header;
        header.transactions_root =
            ioi_types::app::canonical_transaction_root_from_hashes(&tx_hashes)
                .expect("transactions root");
        header.canonical_order_certificate = Some(
            build_committed_surface_canonical_order_certificate(&header, &ordered_transactions)
                .expect("build committed-surface certificate"),
        );
        let collapse =
            ioi_types::app::derive_canonical_collapse_object(&header, &ordered_transactions)
                .expect("derive canonical collapse object");

        let (consensus_kick_tx, mut consensus_kick_rx) = mpsc::unbounded_channel();
        let publisher = GuardianRegistryPublisher {
            workload_client: Arc::new(TestWorkloadClient),
            tx_pool: Arc::new(Mempool::new()),
            consensus_kick_tx,
            nonce_manager: Arc::new(Mutex::new(BTreeMap::new())),
            local_keypair: libp2p::identity::Keypair::generate_ed25519(),
            chain_id: ChainId(1),
        };

        publish_canonical_collapse_object(&publisher, &collapse)
            .await
            .expect("collapse publication should succeed");

        let selected = publisher.tx_pool.select_transactions(8);
        assert_eq!(selected.len(), 1);

        let methods = selected
            .into_iter()
            .map(|tx| match tx {
                ChainTransaction::System(system_tx) => match system_tx.payload {
                    SystemPayload::CallService {
                        service_id, method, ..
                    } => {
                        assert_eq!(service_id, "guardian_registry");
                        method
                    }
                },
                other => panic!("unexpected non-system publication tx: {other:?}"),
            })
            .collect::<Vec<_>>();

        assert_eq!(
            methods,
            vec!["publish_aft_canonical_collapse_object@v1".to_string()]
        );
        consensus_kick_rx
            .try_recv()
            .expect("collapse publication should kick consensus");
        assert!(
            consensus_kick_rx.try_recv().is_err(),
            "expected exactly one kick for the collapse publication"
        );
    }
}
