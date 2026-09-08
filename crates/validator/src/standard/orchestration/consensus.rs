// Path: crates/validator/src/standard/orchestration/consensus.rs
use super::aft_collapse::{
    observe_live_committed_chain_through_block, require_persisted_aft_canonical_collapse_if_needed,
};
use crate::metrics::consensus_metrics as metrics;
use crate::standard::orchestration::context::MainLoopContext;
use crate::standard::orchestration::mempool::Mempool;
use anyhow::{anyhow, Result};
use ioi_api::chain::StateRef;
use ioi_api::crypto::BatchVerifier;
use ioi_api::{
    chain::AnchoredStateView,
    commitment::CommitmentScheme,
    consensus::ConsensusEngine,
    crypto::SerializableKey,
    crypto::SigningKeyPair,
    state::{ProofProvider, StateManager, Verifier},
};

use ioi_crypto::sign::dilithium::MldsaKeyPair;

use ioi_networking::libp2p::{pq_channel::PqChannelLocalConfig, SwarmCommand};
use ioi_networking::traits::NodeState;
use ioi_types::{
    app::{
        account_id_from_key_material, aft_archived_recovered_history_checkpoint_hash_key,
        aft_archived_recovered_history_profile_activation_hash_key,
        aft_archived_recovered_history_profile_activation_key,
        aft_archived_recovered_history_profile_hash_key,
        aft_archived_recovered_history_retention_receipt_key,
        aft_archived_recovered_history_segment_hash_key, aft_archived_recovered_restart_page_key,
        aft_canonical_collapse_object_key, canonical_archived_recovered_history_checkpoint_hash,
        canonical_archived_recovered_history_profile_activation_hash,
        canonical_archived_recovered_history_retention_receipt_hash,
        canonical_archived_recovered_history_segment_hash,
        canonical_archived_recovered_restart_page_hash, canonical_bulletin_close_hash,
        canonical_collapse_historical_continuation_anchor, canonical_order_publication_bundle_hash,
        canonical_recoverable_slot_payload_v5_hash, canonical_validator_set_hash,
        canonical_validator_sets_hash, canonicalize_transactions_for_header, read_validator_sets,
        recover_full_canonical_order_surface_from_share_materials,
        recovered_canonical_header_entry, recovered_certified_header_prefix,
        recovered_restart_block_header_entry, stitch_recovered_canonical_header_segments,
        stitch_recovered_canonical_header_windows, stitch_recovered_certified_header_segments,
        stitch_recovered_certified_header_windows, stitch_recovered_restart_block_header_segments,
        stitch_recovered_restart_block_header_windows, timestamp_millis_to_legacy_seconds,
        to_root_hash, validate_archived_recovered_history_checkpoint_against_profile,
        validate_archived_recovered_history_profile,
        validate_archived_recovered_history_profile_activation_against_checkpoint,
        validate_archived_recovered_history_profile_activation_checkpoint,
        validate_archived_recovered_history_profile_activation_successor,
        validate_archived_recovered_history_retention_receipt_against_profile,
        validate_archived_recovered_history_segment_against_profile,
        validate_archived_recovered_restart_page_against_profile, validate_recovered_page_coverage,
        AccountId, AftHistoricalContinuationSurface, AftRecoveredStateObservationStats,
        AftRecoveredStateSurface, ArchivedRecoveredHistoryCheckpoint,
        ArchivedRecoveredHistoryProfile, ArchivedRecoveredHistoryProfileActivation,
        ArchivedRecoveredHistoryRetentionReceipt, ArchivedRecoveredHistorySegment,
        ArchivedRecoveredRestartPage, Block, BlockHeader, CanonicalCollapseObject,
        ChainTransaction, ConsensusVote, QuorumCertificate, RecoverableSlotPayloadV5,
        RecoveredCanonicalHeaderEntry, RecoveredCertifiedHeaderEntry, RecoveredPublicationBundle,
        RecoveredRestartBlockHeaderEntry, RecoveredSegmentFoldCursor, RecoveredSegmentFoldPage,
        RecoveryShareMaterial, SignatureSuite, StateAnchor, StateRoot, ValidatorSetV1,
        AFT_RECOVERED_PUBLICATION_BUNDLE_PREFIX,
    },
    codec,
    config::AftSafetyMode,
    keys::VALIDATOR_SET_KEY,
};
use parity_scale_codec::{Decode, Encode};
use serde::Serialize;
use std::collections::{BTreeSet, HashMap};
use std::fmt::Debug;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;
use zeroize::{Zeroize, Zeroizing};

fn benchmark_trace_enabled() -> bool {
    std::env::var_os("IOI_AFT_BENCH_TRACE").is_some()
}

fn benchmark_node_label() -> String {
    std::env::var("IOI_AFT_BENCH_NODE_LABEL")
        .ok()
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| format!("pid-{}", std::process::id()))
}

/// The exact local key authorized by the effective validator set for native
/// AFT votes. Transport identity remains Ed25519 and is deliberately separate.
#[derive(Clone)]
pub(crate) enum LocalAftVoteSigner {
    Ed25519(libp2p::identity::Keypair),
    MlDsa44(MldsaKeyPair),
}

impl LocalAftVoteSigner {
    pub(crate) fn suite(&self) -> SignatureSuite {
        match self {
            Self::Ed25519(_) => SignatureSuite::ED25519,
            Self::MlDsa44(_) => SignatureSuite::ML_DSA_44,
        }
    }

    pub(crate) fn public_key(&self) -> Vec<u8> {
        match self {
            Self::Ed25519(keypair) => keypair.public().encode_protobuf(),
            Self::MlDsa44(keypair) => keypair.public_key().to_bytes(),
        }
    }

    pub(crate) fn key_hash(&self) -> Result<[u8; 32]> {
        account_id_from_key_material(self.suite(), &self.public_key())
            .map_err(|error| anyhow!("failed to derive local AFT vote-key hash: {error}"))
    }

    pub(crate) fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        match self {
            Self::Ed25519(keypair) => keypair
                .sign(message)
                .map_err(|error| anyhow!("failed to sign Ed25519 AFT vote: {error}")),
            Self::MlDsa44(keypair) => keypair
                .sign(message)
                .map(|signature| signature.to_bytes())
                .map_err(|error| anyhow!("failed to sign ML-DSA-44 AFT vote: {error}")),
        }
    }
}

/// Selects the local vote key by the rooted authorization record, not by a
/// configuration preference or by the block header's self-description.
pub(crate) fn select_local_aft_vote_signer(
    set: &ValidatorSetV1,
    height: u64,
    ed25519: &libp2p::identity::Keypair,
    ml_dsa_44: Option<&MldsaKeyPair>,
) -> Result<(AccountId, LocalAftVoteSigner)> {
    let mut candidates = vec![LocalAftVoteSigner::Ed25519(ed25519.clone())];
    if let Some(keypair) = ml_dsa_44 {
        candidates.push(LocalAftVoteSigner::MlDsa44(keypair.clone()));
    }

    let mut matches = Vec::new();
    for signer in candidates {
        let key_hash = signer.key_hash()?;
        for validator in &set.validators {
            if validator.consensus_key.suite == signer.suite()
                && validator.consensus_key.public_key_hash == key_hash
                && validator.consensus_key.since_height <= height
            {
                matches.push((validator.account_id, signer.clone()));
            }
        }
    }
    match matches.as_slice() {
        [(account_id, signer)] => Ok((*account_id, signer.clone())),
        [] => Err(anyhow!(
            "neither local Ed25519 nor configured ML-DSA-44 key is authorized by the effective AFT validator set at height {height}"
        )),
        _ => Err(anyhow!(
            "multiple local signing keys are authorized by the effective AFT validator set at height {height}; refusing ambiguous identity"
        )),
    }
}

pub(crate) struct AftPqChannelConfiguration {
    pub(crate) local: PqChannelLocalConfig,
    pub(crate) peer_keys: HashMap<AccountId, [u8; 32]>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AftPqLocalRole {
    ActiveMember(AccountId),
    HandoffOnlySuccessor(AccountId),
}

pub(crate) struct AftPqStartupRoot<'a> {
    pub(crate) rooted: &'a ValidatorSetV1,
    pub(crate) handoff_successor: Option<&'a ValidatorSetV1>,
    pub(crate) recovery_required: bool,
}

/// Resolve the PQ transport/authority root used at process startup. A QUV
/// transition deliberately remains rooted in `current` even after `next`
/// becomes effective: restart must recover the local live-install gate before
/// it can acquire successor authority.
pub(crate) fn select_aft_pq_startup_root(
    sets: &ioi_types::app::ValidatorSetsV1,
    observation_height: u64,
    quv_enabled: bool,
) -> Result<AftPqStartupRoot<'_>> {
    let effective = ioi_types::app::effective_set_for_height(sets, observation_height);
    if !quv_enabled {
        return Ok(AftPqStartupRoot {
            rooted: effective,
            handoff_successor: None,
            recovery_required: false,
        });
    }
    let old_root =
        ioi_types::app::canonical_validator_set_hash(&sets.current).map_err(anyhow::Error::msg)?;
    let handoff_successor = sets
        .next
        .as_ref()
        .filter(|next| !next.validators.is_empty() && next.total_weight > 0)
        .filter(|next| {
            ioi_types::app::canonical_validator_set_hash(next)
                .map(|root| root != old_root)
                .unwrap_or(true)
        });
    let Some(successor) = handoff_successor else {
        return Ok(AftPqStartupRoot {
            rooted: effective,
            handoff_successor: None,
            recovery_required: false,
        });
    };
    // Surface malformed successors as configuration errors rather than
    // accidentally classifying them as a transition.
    ioi_types::app::canonical_validator_set_hash(successor).map_err(anyhow::Error::msg)?;
    Ok(AftPqStartupRoot {
        rooted: &sets.current,
        handoff_successor: Some(successor),
        recovery_required: observation_height >= successor.effective_from_height,
    })
}

/// Classify one local ML-DSA identity without letting successor enrollment
/// imply current consensus authority. An active match always wins for an
/// overlapping handoff; a successor-only match is available only to QUV.
pub(crate) fn select_aft_pq_local_role(
    effective: &ValidatorSetV1,
    staged_successor: Option<&ValidatorSetV1>,
    identity_key_hash: [u8; 32],
    observation_height: u64,
    quv_enabled: bool,
) -> Result<AftPqLocalRole> {
    let active = effective
        .validators
        .iter()
        .filter(|validator| {
            validator.consensus_key.public_key_hash == identity_key_hash
                && validator.consensus_key.since_height <= observation_height
        })
        .map(|validator| validator.account_id)
        .collect::<Vec<_>>();
    match active.as_slice() {
        [account] => return Ok(AftPqLocalRole::ActiveMember(*account)),
        [] => {}
        _ => {
            return Err(anyhow!(
                "local ML-DSA signer is ambiguously enrolled in the effective AFT set"
            ))
        }
    }
    if !quv_enabled {
        return Err(anyhow!(
            "local ML-DSA signer is not enrolled in the effective AFT set"
        ));
    }
    let staged = staged_successor
        .into_iter()
        .flat_map(|successor| {
            successor
                .validators
                .iter()
                .map(move |validator| (successor, validator))
        })
        .filter(|(successor, validator)| {
            validator.consensus_key.public_key_hash == identity_key_hash
                && validator.consensus_key.since_height <= successor.effective_from_height
        })
        .map(|(_, validator)| validator.account_id)
        .collect::<Vec<_>>();
    match staged.as_slice() {
        [account] => Ok(AftPqLocalRole::HandoffOnlySuccessor(*account)),
        [] => Err(anyhow!(
            "local ML-DSA signer belongs to neither the effective set nor the staged QUV successor set"
        )),
        _ => Err(anyhow!(
            "local ML-DSA signer is ambiguously enrolled in the staged QUV successor set"
        )),
    }
}

/// Refusal emitted by every path that would otherwise let a process without a
/// successor identity follow successor-root history.
pub(crate) const QUV_RETIRED_SIGNER_REFUSAL: &str =
    "local ML-DSA signer belongs to neither the effective set nor the staged QUV successor set";

/// Whether a block at `height` may enter this process while a QUV successor
/// is staged but not yet activated by the process-local live-install gate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum QuvSuccessorRootGate {
    /// No staged, unactivated QUV successor governs `height`.
    Admit,
    /// The local process is a staged successor whose durable install gate has
    /// not activated yet. Successor-root bytes must wait for that gate; they
    /// never activate it.
    DeferUntilLocalInstall,
    /// The local process holds no successor identity. It is retired at
    /// `height` and must stop rather than adopt successor-root history from
    /// synced or gossiped bytes.
    RefuseRetired,
}

/// Successor authority is granted only by the process-local durable
/// live-install gate. Blocks at or beyond the staged activation height are
/// therefore not adopted from sync or gossip while `staged_successor` is still
/// pending in this process: a successor defers until its own gate activates,
/// and an old-only member refuses. Heights below activation, ordinary
/// (non-QUV) rotations, and processes with no pending staged successor are
/// unaffected.
pub(crate) fn quv_successor_root_gate(
    handoff_enabled: bool,
    staged_successor: Option<&ValidatorSetV1>,
    local_has_install_gate: bool,
    height: u64,
) -> QuvSuccessorRootGate {
    if !handoff_enabled {
        return QuvSuccessorRootGate::Admit;
    }
    let Some(successor) = staged_successor else {
        return QuvSuccessorRootGate::Admit;
    };
    if height < successor.effective_from_height {
        return QuvSuccessorRootGate::Admit;
    }
    if local_has_install_gate {
        QuvSuccessorRootGate::DeferUntilLocalInstall
    } else {
        QuvSuccessorRootGate::RefuseRetired
    }
}

pub(crate) fn aft_pq_outbox_path(
    root: Option<&str>,
    configuration_hash: [u8; 32],
    account_id: AccountId,
) -> Result<PathBuf> {
    let root = root
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| anyhow!("strict PQ AFT channels require aft_pq_outbox_dir"))?;
    Ok(Path::new(root)
        .join(hex::encode(configuration_hash))
        .join(format!("{}.scale", hex::encode(account_id.as_ref()))))
}

pub(crate) fn aft_fallback_journal_path(
    root: Option<&str>,
    configuration_hash: [u8; 32],
    account_id: AccountId,
) -> Result<PathBuf> {
    let root = root
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| anyhow!("normative PQ AFT fallback requires aft_pq_outbox_dir"))?;
    Ok(Path::new(root)
        .join(hex::encode(configuration_hash))
        .join(format!(
            "{}.fallback.scale",
            hex::encode(account_id.as_ref())
        )))
}

pub(crate) struct AftAsyncStoragePaths {
    pub(crate) node_journal: PathBuf,
    pub(crate) proposal_root: PathBuf,
    pub(crate) node_anchor: PathBuf,
    pub(crate) signing_fence_state: PathBuf,
    pub(crate) signing_fence_anchor: PathBuf,
    pub(crate) quv_member_state: PathBuf,
    pub(crate) quv_member_anchor: PathBuf,
    pub(crate) quv_handoff_state: PathBuf,
    pub(crate) quv_handoff_anchor: PathBuf,
}

/// Resolves disjoint snapshot-state and externally controlled anchor paths.
/// Either root containing the other is refused because a single clone/rollback
/// boundary would then defeat the monotone anchor.
pub(crate) fn aft_async_storage_paths(
    state_root: Option<&str>,
    anchor_root: Option<&str>,
    configuration_hash: [u8; 32],
    account_id: AccountId,
    height: u64,
) -> Result<AftAsyncStoragePaths> {
    let state_root = Path::new(
        state_root
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| anyhow!("normative PQ AFT fallback requires aft_pq_outbox_dir"))?,
    );
    let anchor_root = Path::new(
        anchor_root
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| anyhow!("normative PQ AFT fallback requires aft_external_anchor_dir"))?,
    );
    std::fs::create_dir_all(state_root)?;
    std::fs::create_dir_all(anchor_root)?;
    let state_canonical = std::fs::canonicalize(state_root)?;
    let anchor_canonical = std::fs::canonicalize(anchor_root)?;
    if state_canonical == anchor_canonical
        || state_canonical.starts_with(&anchor_canonical)
        || anchor_canonical.starts_with(&state_canonical)
    {
        return Err(anyhow!(
            "AFT asynchronous state and external-anchor roots must have disjoint snapshot boundaries"
        ));
    }
    let configuration = hex::encode(configuration_hash);
    let account = hex::encode(account_id.as_ref());
    let state_scope = state_root.join(&configuration).join(&account);
    let anchor_scope = anchor_root.join(configuration).join(account);
    Ok(AftAsyncStoragePaths {
        node_journal: state_scope
            .join("hash-async")
            .join(height.to_string())
            .join("node.scale"),
        proposal_root: state_scope
            .join("hash-async")
            .join(height.to_string())
            .join("proposals"),
        node_anchor: anchor_scope
            .join("hash-async")
            .join(format!("{height}.anchor")),
        signing_fence_state: state_scope.join("cross-path-signing-fence.scale"),
        signing_fence_anchor: anchor_scope.join("cross-path-signing-fence.anchor"),
        quv_member_state: state_scope.join("quv-member-v0.scale"),
        quv_member_anchor: anchor_scope.join("quv-member-v0.anchor"),
        quv_handoff_state: state_scope.join("quv-handoff-v0.scale"),
        quv_handoff_anchor: anchor_scope.join("quv-handoff-v0.anchor"),
    })
}

/// Derives a purpose-separated journal custody key from the enrolled ML-DSA
/// secret. The intermediate secret-bearing buffers are zeroized immediately.
pub(crate) fn derive_aft_async_custody_key(
    signer: &MldsaKeyPair,
    network_id: [u8; 32],
    configuration_hash: [u8; 32],
    account_id: AccountId,
) -> Result<Zeroizing<[u8; 32]>> {
    let mut private_key = signer.private_key().to_bytes();
    let mut material = codec::to_bytes_canonical(&(
        b"ioi/aft/hash-async-runtime-custody/v1".to_vec(),
        &private_key,
        network_id,
        configuration_hash,
        account_id,
    ))
    .map_err(anyhow::Error::msg)?;
    let derived = ioi_crypto::algorithms::hash::sha256(&material)?;
    private_key.zeroize();
    material.zeroize();
    Ok(Zeroizing::new(derived))
}

/// Derive a purpose-separated rollback-anchor key for the successor's Q-EA7
/// install gate. This key authenticates local monotone state; it grants no
/// old-root signing or consensus authority.
pub(crate) fn derive_aft_quv_handoff_custody_key(
    signer: &MldsaKeyPair,
    network_id: [u8; 32],
    old_configuration_hash: [u8; 32],
    successor_account: AccountId,
) -> Result<Zeroizing<[u8; 32]>> {
    let mut private_key = signer.private_key().to_bytes();
    let mut material = codec::to_bytes_canonical(&(
        b"ioi/aft/quv-handoff-runtime-custody/v0".to_vec(),
        &private_key,
        network_id,
        old_configuration_hash,
        successor_account,
    ))
    .map_err(anyhow::Error::msg)?;
    let derived = ioi_crypto::algorithms::hash::sha256(&material)?;
    private_key.zeroize();
    material.zeroize();
    Ok(Zeroizing::new(derived))
}

/// Builds the strict PQ carrier configuration only for a uniformly ML-DSA
/// effective validator set. Mixed/classical sets remain a separately labelled
/// compatibility profile and never acquire `channel_pq=true` by inference.
pub(crate) fn build_aft_pq_channel_configuration(
    set: &ValidatorSetV1,
    activation_height: u64,
    network_id: [u8; 32],
    peer_id: libp2p::PeerId,
    pq_signer: Option<&MldsaKeyPair>,
    outbox_root: Option<&str>,
) -> Result<Option<AftPqChannelConfiguration>> {
    if set.validators.is_empty()
        || !set
            .validators
            .iter()
            .all(|validator| validator.consensus_key.suite == SignatureSuite::ML_DSA_44)
    {
        return Ok(None);
    }
    let pq_signer = pq_signer
        .ok_or_else(|| anyhow!("all-ML-DSA AFT configuration requires a local ML-DSA signer"))?;
    let identity = pq_signer.clone();
    let identity_key_hash =
        account_id_from_key_material(SignatureSuite::ML_DSA_44, &identity.public_key().to_bytes())
            .map_err(|error| anyhow!(error))?;
    let matches = set
        .validators
        .iter()
        .filter(|validator| {
            validator.consensus_key.public_key_hash == identity_key_hash
                && validator.consensus_key.since_height <= activation_height
        })
        .map(|validator| validator.account_id)
        .collect::<Vec<_>>();
    let account_id = match matches.as_slice() {
        [account_id] => *account_id,
        [] => {
            return Err(anyhow!(
                "local ML-DSA signer is not enrolled in the effective AFT set"
            ))
        }
        _ => {
            return Err(anyhow!(
                "local ML-DSA signer is ambiguously enrolled more than once"
            ))
        }
    };
    let configuration_hash = canonical_validator_set_hash(set).map_err(anyhow::Error::msg)?;
    let outbox_path = aft_pq_outbox_path(outbox_root, configuration_hash, account_id)?;
    Ok(Some(AftPqChannelConfiguration {
        local: PqChannelLocalConfig {
            network_id,
            configuration_hash,
            epoch: set.effective_from_height,
            account_id,
            peer_id,
            identity,
            identity_key_hash,
            outbox_path,
            rooted_accounts: set
                .validators
                .iter()
                .map(|member| member.account_id)
                .collect(),
        },
        peer_keys: set
            .validators
            .iter()
            .map(|validator| {
                (
                    validator.account_id,
                    validator.consensus_key.public_key_hash,
                )
            })
            .collect(),
    }))
}

pub(crate) const AFT_RECOVERED_CONSENSUS_HEADER_WINDOW: u64 = 5;
pub(crate) const AFT_RECOVERED_CONSENSUS_HEADER_STITCH_OVERLAP: u64 = 2;
pub(crate) const DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_WINDOW_BUDGET: u64 = 5;
const MAX_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_WINDOW_BUDGET: u64 = 8;
pub(crate) const DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_SEGMENT_BUDGET: u64 = 4;
const MAX_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_SEGMENT_BUDGET: u64 = 8;
pub(crate) const DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_SEGMENT_FOLD_BUDGET: u64 = 2;
const MAX_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_SEGMENT_FOLD_BUDGET: u64 = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
struct RecoveredConsensusTipAnchor {
    height: u64,
    state_root: Vec<u8>,
    block_hash: [u8; 32],
}

mod production;
mod recovery;
#[cfg(test)]
mod tests;

pub use self::production::drive_consensus_tick;
pub(crate) use self::production::{
    recovered_consensus_header_stitch_segment_budget,
    recovered_consensus_header_stitch_window_budget, trim_candidate_transactions_to_byte_budget,
    verify_batch_and_filter,
};
use self::recovery::*;
