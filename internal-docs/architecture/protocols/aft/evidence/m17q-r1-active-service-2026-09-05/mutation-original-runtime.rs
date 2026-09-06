//! Production boundary for the separately named `aft_quv_v0` profile.
//!
//! Incoming requests are admitted only against an independently provisioned
//! domain policy. The candidate cannot nominate its own owner. Durable member
//! mutation runs off the async reactor and no reply is queued until the state
//! and external rollback anchor have both been synchronized.

pub(super) mod admission;
mod dispatch;
use dispatch::QuvDispatchV0;

use super::context::MainLoopContext;
use anyhow::{anyhow, Result};
use ioi_api::{
    commitment::CommitmentScheme,
    consensus::ConsensusEngine,
    crypto::{SerializableKey, SigningKeyPair},
    state::{StateManager, Verifier},
};
use ioi_consensus::aft::authenticated_quorum::{
    pq_optimistic_quorum_geometry, verify_quorum_certificate,
};
use ioi_consensus::aft::query_unanimity::{
    quv_handoff_domain_id, quv_handoff_initial_predecessor, quv_handoff_payload_hash,
    quv_policy_root, validate_quv_handoff_candidate, QuvCandidateValidatorV0, QuvError,
    QuvMemberSignerV0, QuvOnlineAuthorizationV0, QuvOnlineOperationV0,
    RootedQuvCandidateValidatorV0, RootedQuvReplyVerifierV0,
};
use ioi_crypto::sign::dilithium::MldsaKeyPair;
use ioi_networking::libp2p::{pq_channel::PqPeerEnrollment, SwarmCommand};
use ioi_types::{
    app::{
        canonical_validator_set_hash, AccountId, ChainTransaction, QuorumCertificate,
        QuvAuthorityModeV0, QuvCandidateV0, QuvConfigurationHandoffEnvelopeV0,
        QuvConfigurationHandoffV0, QuvNonce, QuvPushQueryV0, QuvReplyV0, QuvSlotV0,
    },
    codec,
    config::{AftQuvDomainPolicyV0, AftSafetyMode},
};
use libp2p::PeerId;
use parity_scale_codec::{Decode, Encode};
use rand::{rngs::OsRng, RngCore};
use serde::Serialize;
use std::{
    collections::BTreeSet,
    ffi::OsString,
    fmt::Debug,
    fs::{File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::{oneshot, Mutex, OwnedSemaphorePermit};

pub(super) struct PendingQuvOperationV0 {
    admission: OwnedSemaphorePermit,
    dispatch: QuvDispatchV0,
    service_deadline: Option<Instant>,
    operation: QuvOnlineOperationV0,
    completion: oneshot::Sender<std::result::Result<QuvOnlineAuthorizationV0, anyhow::Error>>,
}

fn finish_active_service<T>(
    outcome: Result<T>,
    deadline: Option<Instant>,
    observed: Instant,
) -> Result<T> {
    if deadline.is_some_and(|deadline| observed >= deadline) {
        return Err(anyhow!(
            "QUV preparation active service deadline exceeded; inspect durable history"
        ));
    }
    outcome
}

struct RuntimeQuvSignerV0 {
    member: AccountId,
    signer: MldsaKeyPair,
}

impl QuvMemberSignerV0 for RuntimeQuvSignerV0 {
    fn member(&self) -> &AccountId {
        &self.member
    }

    fn sign_reply(&self, signing_bytes: &[u8]) -> std::result::Result<Vec<u8>, QuvError> {
        self.signer
            .sign(signing_bytes)
            .map(|signature| signature.to_bytes())
            .map_err(|error| QuvError::Signing(error.to_string()))
    }
}

fn provisioned_policy<'a>(
    policies: &'a [AftQuvDomainPolicyV0],
    query: &QuvPushQueryV0,
) -> Result<&'a AftQuvDomainPolicyV0> {
    let policy = policies
        .iter()
        .find(|policy| policy.domain_id == query.candidate.slot.domain_id)
        .ok_or_else(|| anyhow!("QUV request names no independently provisioned domain"))?;
    if policy.authority_mode != query.candidate.slot.authority_mode {
        return Err(anyhow!(
            "QUV request authority mode differs from provisioned policy"
        ));
    }
    match policy.bootstrap {
        ioi_types::app::QuvDomainBootstrapV0::Fixed {
            initial_slot,
            predecessor,
        } => {
            if query.candidate.slot.slot < initial_slot
                || (query.candidate.slot.slot == initial_slot
                    && query.candidate.slot.predecessor != predecessor)
            {
                return Err(anyhow!(
                    "QUV request differs from the rooted bootstrap boundary"
                ));
            }
        }
        ioi_types::app::QuvDomainBootstrapV0::HandoffBoundary { activation_height } => {
            if query.candidate.slot.slot != activation_height {
                return Err(anyhow!("QUV request differs from the rooted handoff slot"));
            }
        }
    }
    // Later fixed-domain slots still require the separate durable expected-head
    // mechanism. Bootstrap checks cannot establish acceptance of a parent.
    Ok(policy)
}

fn require_qualified_membership(
    policy: &AftQuvDomainPolicyV0,
    membership_len: usize,
) -> Result<()> {
    if membership_len == 0 || membership_len > usize::from(policy.qualified_max_configured_members)
    {
        return Err(anyhow!(
            "QUV rooted membership exceeds the deployment-qualified member envelope"
        ));
    }
    Ok(())
}

fn provisioned_policy_root(
    policy: &AftQuvDomainPolicyV0,
) -> std::result::Result<[u8; 32], QuvError> {
    quv_policy_root(
        policy.domain_id,
        policy.authority_mode,
        policy.owner,
        policy.delta_rt_millis,
        policy.continuation_millis,
        &policy.bootstrap,
        &policy.preparation,
    )
}

pub(super) fn member_provisioning_root(
    network_id: [u8; 32],
    configuration_root: [u8; 32],
    policies: &[AftQuvDomainPolicyV0],
) -> std::result::Result<[u8; 32], QuvError> {
    let roots = policies
        .iter()
        .map(|policy| Ok((policy.domain_id, provisioned_policy_root(policy)?)))
        .collect::<std::result::Result<Vec<_>, QuvError>>()?;
    ioi_consensus::aft::query_unanimity::quv_member_provisioning_root(
        network_id,
        configuration_root,
        &roots,
    )
}

pub(super) fn member_provisioned_domains(
    network_id: [u8; 32],
    configuration_root: [u8; 32],
    policies: &[AftQuvDomainPolicyV0],
) -> std::result::Result<
    std::collections::BTreeMap<[u8; 32], ioi_consensus::aft::query_unanimity::QuvMemberDomainV0>,
    QuvError,
> {
    let mut domains = std::collections::BTreeMap::new();
    for policy in policies {
        let domain =
            ioi_consensus::aft::query_unanimity::QuvMemberDomainV0::from_provisioned_bootstrap(
                configuration_root,
                provisioned_policy_root(policy)?,
                network_id,
                policy.domain_id,
                policy.authority_mode,
                &policy.bootstrap,
            )?;
        if domains.insert(policy.domain_id, domain).is_some() {
            return Err(QuvError::InvalidStoreConfiguration);
        }
    }
    Ok(domains)
}

const QUV_HANDOFF_SOURCE_MAX_BYTES_V0: u64 = 16 * 1024 * 1024;

fn handoff_draft_path(source: &str) -> PathBuf {
    let mut path = OsString::from(source);
    path.push(".draft");
    PathBuf::from(path)
}

/// Persist a non-authoritative handoff draft without exposing partial bytes.
/// The draft contains no owner signature and can never pass source admission;
/// it exists only to give the owner the exact pre-publication block coordinates
/// that must be signed to release the old-root boundary.
fn persist_handoff_draft(
    source: &str,
    envelope: &QuvConfigurationHandoffEnvelopeV0,
) -> Result<PathBuf> {
    let path = handoff_draft_path(source);
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)
        .map_err(|error| anyhow!("failed to create QUV handoff draft directory: {error}"))?;
    let bytes = codec::to_bytes_canonical(envelope)
        .map_err(|error| anyhow!("failed to encode QUV handoff draft: {error}"))?;
    let file_name = path
        .file_name()
        .ok_or_else(|| anyhow!("QUV handoff draft path has no file name"))?
        .to_string_lossy();
    let temporary = parent.join(format!(".{file_name}.tmp.{}", std::process::id()));
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&temporary)
        .map_err(|error| anyhow!("failed to open temporary QUV handoff draft: {error}"))?;
    file.write_all(&bytes)
        .map_err(|error| anyhow!("failed to write temporary QUV handoff draft: {error}"))?;
    file.sync_all()
        .map_err(|error| anyhow!("failed to sync temporary QUV handoff draft: {error}"))?;
    std::fs::rename(&temporary, &path)
        .map_err(|error| anyhow!("failed to publish QUV handoff draft: {error}"))?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| anyhow!("failed to sync QUV handoff draft directory: {error}"))?;
    Ok(path)
}

pub(crate) fn read_handoff_source(path: &str) -> Result<QuvConfigurationHandoffEnvelopeV0> {
    let metadata = std::fs::metadata(path)
        .map_err(|error| anyhow!("failed to stat QUV handoff source: {error}"))?;
    if !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > QUV_HANDOFF_SOURCE_MAX_BYTES_V0
    {
        return Err(anyhow!(
            "QUV handoff source must be a nonempty regular file no larger than {} bytes",
            QUV_HANDOFF_SOURCE_MAX_BYTES_V0
        ));
    }
    let bytes = std::fs::read(path)
        .map_err(|error| anyhow!("failed to read QUV handoff source: {error}"))?;
    codec::from_bytes_canonical(&bytes)
        .map_err(|error| anyhow!("invalid canonical QUV handoff source: {error}"))
}

fn validate_handoff_source(
    envelope: &QuvConfigurationHandoffEnvelopeV0,
    old_set: &ioi_types::app::ValidatorSetV1,
    staged_successor: &ioi_types::app::ValidatorSetV1,
    keys: &ioi_consensus::aft::authenticated_quorum::ValidatorKeyRegistry,
    policies: &[AftQuvDomainPolicyV0],
    network_id: [u8; 32],
    safety_mode: AftSafetyMode,
) -> Result<()> {
    let old_root = canonical_validator_set_hash(old_set).map_err(anyhow::Error::msg)?;
    if envelope.handoff.network_id != network_id
        || envelope.handoff.old_configuration_root != old_root
        || codec::to_bytes_canonical(&envelope.handoff.successor_set).map_err(anyhow::Error::msg)?
            != codec::to_bytes_canonical(staged_successor).map_err(anyhow::Error::msg)?
    {
        return Err(anyhow!(
            "QUV handoff source differs from the rooted old/staged configuration"
        ));
    }
    validate_quv_handoff_candidate(&envelope.candidate, &envelope.handoff)?;
    let threshold = pq_optimistic_quorum_geometry(old_set)?.q as usize;
    verify_quorum_certificate(
        &envelope.handoff.boundary_qc,
        old_set,
        keys,
        safety_mode,
        threshold,
    )?;
    let query = QuvPushQueryV0 {
        verifier_nonce: [1; 32],
        candidate: envelope.candidate.clone(),
    };
    let policy = provisioned_policy(policies, &query)?;
    if policy.bootstrap
        != (ioi_types::app::QuvDomainBootstrapV0::HandoffBoundary {
            activation_height: envelope.handoff.activation_height,
        })
    {
        return Err(anyhow!(
            "QUV handoff source requires its exact rooted boundary bootstrap"
        ));
    }
    let validator = RootedQuvCandidateValidatorV0::new(
        old_set,
        keys,
        envelope.handoff.old_authority_expiry_height,
        network_id,
        provisioned_policy_root(policy)?,
        policy.owner,
    )?;
    validator.validate_candidate(&envelope.candidate)?;
    Ok(())
}

fn require_exact_handoff_boundary(
    block: &ioi_types::app::Block<ChainTransaction>,
    envelope: &QuvConfigurationHandoffEnvelopeV0,
    provenance: &str,
) -> Result<()> {
    let block_hash: [u8; 32] = block
        .header
        .hash()
        .map_err(|error| anyhow!(error.to_string()))?
        .try_into()
        .map_err(|_| anyhow!("QUV handoff block hash is not 32 bytes"))?;
    if block.header.height != envelope.handoff.state_height
        || block.header.height != envelope.handoff.old_authority_expiry_height
        || block_hash != envelope.handoff.state_block_hash
        || block.header.state_root.0 != envelope.handoff.state_root
    {
        return Err(anyhow!(
            "{provenance} does not match the owner-signed QUV handoff boundary"
        ));
    }
    Ok(())
}

/// Refresh and authenticate the independently provisioned handoff source.
/// The resulting bytes remain candidate input; this function creates no
/// process-local authorization and does not touch the successor install gate.
pub(crate) async fn refresh_handoff_source<CS, ST, CE, V>(
    context_arc: &Arc<Mutex<MainLoopContext<CS, ST, CE, V>>>,
) -> Result<QuvConfigurationHandoffEnvelopeV0>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + Debug
        + Clone,
    <CS as CommitmentScheme>::Commitment: Send + Sync + Debug,
    CE: ConsensusEngine<ChainTransaction> + Send + Sync + 'static,
    <CS as CommitmentScheme>::Proof: Serialize
        + for<'de> serde::Deserialize<'de>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug
        + Encode
        + Decode,
{
    let (path, old_set, staged, keys, policies, network_id, safety_mode) = {
        let context = context_arc.lock().await;
        let path = context
            .config
            .aft_quv_handoff_source
            .as_ref()
            .cloned()
            .ok_or_else(|| anyhow!("no independently provisioned QUV handoff source"))?;
        let (old_set, keys) = context
            .aft_async_membership
            .as_ref()
            .ok_or_else(|| anyhow!("QUV handoff source has no rooted old membership"))?;
        let staged = context
            .aft_quv_staged_successor
            .as_ref()
            .cloned()
            .ok_or_else(|| anyhow!("QUV handoff source has no canonical staged successor"))?;
        (
            path,
            old_set.clone(),
            staged,
            keys.clone(),
            context.config.aft_quv_domain_policies.clone(),
            context.genesis_hash,
            context.config.aft_safety_mode,
        )
    };
    let envelope = tokio::task::spawn_blocking(move || read_handoff_source(&path))
        .await
        .map_err(|error| anyhow!("QUV handoff source task failed: {error}"))??;
    validate_handoff_source(
        &envelope,
        &old_set,
        &staged,
        &keys,
        &policies,
        network_id,
        safety_mode,
    )?;
    context_arc.lock().await.aft_quv_handoff_envelope = Some(envelope.clone());
    Ok(envelope)
}

/// Export the exact unsigned owner ceremony input for a verified QC-certified
/// final old-root block. This is data availability, not authorization: the
/// empty authority signature makes the draft unusable by every QUV verifier
/// until the configured owner signs the candidate and provisions the source.
async fn publish_handoff_draft_for_block<CS, ST, CE, V>(
    context_arc: &Arc<Mutex<MainLoopContext<CS, ST, CE, V>>>,
    block: &ioi_types::app::Block<ChainTransaction>,
    qc: &QuorumCertificate,
    next_height: u64,
) -> Result<PathBuf>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + Debug
        + Clone,
    <CS as CommitmentScheme>::Commitment: Send + Sync + Debug,
    CE: ConsensusEngine<ChainTransaction> + Send + Sync + 'static,
    <CS as CommitmentScheme>::Proof: Serialize
        + for<'de> serde::Deserialize<'de>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug
        + Encode
        + Decode,
{
    let (source, network_id, old_set, successor, policies) = {
        let context = context_arc.lock().await;
        let source = context
            .config
            .aft_quv_handoff_source
            .clone()
            .ok_or_else(|| anyhow!("no independently provisioned QUV handoff source"))?;
        let old_set = context
            .aft_async_membership
            .as_ref()
            .map(|(set, _)| set.clone())
            .ok_or_else(|| anyhow!("QUV handoff draft has no rooted old membership"))?;
        let successor = context
            .aft_quv_staged_successor
            .clone()
            .ok_or_else(|| anyhow!("QUV handoff draft has no canonical staged successor"))?;
        (
            source,
            context.genesis_hash,
            old_set,
            successor,
            context.config.aft_quv_domain_policies.clone(),
        )
    };
    if successor.effective_from_height != next_height || block.header.height + 1 != next_height {
        return Err(anyhow!(
            "QUV handoff draft does not describe the adjacent final old-root block"
        ));
    }
    let old_root = canonical_validator_set_hash(&old_set).map_err(anyhow::Error::msg)?;
    let successor_root = canonical_validator_set_hash(&successor).map_err(anyhow::Error::msg)?;
    let domain_id = quv_handoff_domain_id(network_id, old_root, successor_root, next_height)?;
    let policy = policies
        .iter()
        .find(|policy| policy.domain_id == domain_id)
        .ok_or_else(|| anyhow!("QUV handoff draft has no exact derived-domain policy"))?;
    if policy.authority_mode != QuvAuthorityModeV0::Owned {
        return Err(anyhow!(
            "QUV configuration handoff requires an owned authority policy"
        ));
    }
    let owner = policy
        .owner
        .ok_or_else(|| anyhow!("QUV configuration handoff policy has no owner"))?;
    let state_block_hash: [u8; 32] = block
        .header
        .hash()
        .map_err(|error| anyhow!(error.to_string()))?
        .try_into()
        .map_err(|_| anyhow!("QUV handoff block hash is not 32 bytes"))?;
    let predecessor = quv_handoff_initial_predecessor(
        network_id,
        old_root,
        next_height,
        block.header.height,
        state_block_hash,
        &block.header.state_root.0,
    )?;
    let handoff = QuvConfigurationHandoffV0 {
        network_id,
        old_configuration_root: old_root,
        successor_set: successor,
        activation_height: next_height,
        old_authority_expiry_height: block.header.height,
        predecessor_candidate_hash: predecessor,
        state_height: block.header.height,
        state_block_hash,
        state_root: block.header.state_root.0.clone(),
        boundary_qc: qc.clone(),
    };
    let candidate = QuvCandidateV0 {
        slot: QuvSlotV0 {
            configuration_root: old_root,
            policy_root: provisioned_policy_root(policy)?,
            network_id,
            domain_id,
            slot: next_height,
            predecessor,
            authority_mode: QuvAuthorityModeV0::Owned,
        },
        payload_hash: quv_handoff_payload_hash(&handoff)?,
        authorizer: owner,
        authority_signature: Vec::new(),
    };
    let envelope = QuvConfigurationHandoffEnvelopeV0 { handoff, candidate };
    tokio::task::spawn_blocking(move || persist_handoff_draft(&source, &envelope))
        .await
        .map_err(|error| anyhow!("QUV handoff draft task failed: {error}"))?
}

/// Record a verified old-root QC and export the corresponding owner-ceremony
/// input only when it certifies the exact locally executed transition
/// boundary. The QC breaks the descendant-finality/reconfiguration cycle but
/// supplies ordering evidence only: successor authority still requires the
/// fresh online QUV operation against the old membership.
pub(crate) async fn observe_certified_handoff<CS, ST, CE, V>(
    context_arc: &Arc<Mutex<MainLoopContext<CS, ST, CE, V>>>,
    qc: &QuorumCertificate,
) -> Result<()>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + Debug
        + Clone,
    <CS as CommitmentScheme>::Commitment: Send + Sync + Debug,
    CE: ConsensusEngine<ChainTransaction> + Send + Sync + 'static,
    <CS as CommitmentScheme>::Proof: Serialize
        + for<'de> serde::Deserialize<'de>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug
        + Encode
        + Decode,
    V: Verifier<Commitment = CS::Commitment, Proof = CS::Proof>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug,
{
    let Some((block, next_height, workload)) = ({
        let context = context_arc.lock().await;
        let candidate = context
            .aft_quv_staged_successor
            .as_ref()
            .zip(context.last_executed_block.as_ref())
            .filter(|(successor, block)| {
                block.header.height.saturating_add(1) == successor.effective_from_height
                    && qc.height == block.header.height
                    && qc.view == block.header.view
                    && block
                        .header
                        .hash()
                        .ok()
                        .and_then(|hash| <[u8; 32]>::try_from(hash).ok())
                        == Some(qc.block_hash)
            })
            .map(|(successor, block)| {
                (
                    block.clone(),
                    successor.effective_from_height,
                    context.view_resolver.workload_client().clone(),
                )
            });
        candidate
    }) else {
        return Ok(());
    };
    let parent_height = block.header.height.checked_sub(1).ok_or_else(|| {
        anyhow!("QUV handoff boundary cannot use the height-zero block as a transition")
    })?;
    let parent = workload
        .get_block_by_height(parent_height)
        .await?
        .ok_or_else(|| anyhow!("QUV handoff boundary predecessor is unavailable"))?;
    let parent_hash: [u8; 32] = parent
        .header
        .hash()
        .map_err(|error| anyhow!(error.to_string()))?
        .try_into()
        .map_err(|_| anyhow!("QUV handoff predecessor hash is not 32 bytes"))?;
    if parent_hash != block.header.parent_hash
        || parent.header.state_root.0 != block.header.parent_state_root.0
    {
        return Err(anyhow!(
            "QUV handoff boundary does not extend its locally retained predecessor"
        ));
    }
    {
        let mut context = context_arc.lock().await;
        context.aft_quv_certified_handoff = Some(qc.clone());
        context.aft_quv_certified_handoff_block = Some(block.clone());
        context.aft_quv_certified_handoff_parent_block = Some(parent);
    }
    let draft_path = publish_handoff_draft_for_block(context_arc, &block, qc, next_height).await?;
    tracing::info!(
        target: "quv",
        height = block.header.height,
        next_height,
        path = %draft_path.display(),
        qc_view = qc.view,
        "Published exact QC-certified QUV owner-ceremony draft"
    );
    Ok(())
}

/// Execute the successor process's own online old-root operation and consume
/// its non-exportable result directly into the rollback-anchored activation
/// store. No transcript or cached verifier assertion enters this path.
pub(crate) enum HandoffInstallOutcome {
    ExistingGate([u8; 32]),
    FreshLiveInstall([u8; 32]),
}

impl HandoffInstallOutcome {
    fn configuration_root(&self) -> [u8; 32] {
        match self {
            Self::ExistingGate(root) | Self::FreshLiveInstall(root) => *root,
        }
    }
}

pub(crate) async fn authorize_and_install_handoff<CS, ST, CE, V>(
    context_arc: &Arc<Mutex<MainLoopContext<CS, ST, CE, V>>>,
) -> Result<HandoffInstallOutcome>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + Debug
        + Clone,
    <CS as CommitmentScheme>::Commitment: Send + Sync + Debug,
    CE: ConsensusEngine<ChainTransaction> + Send + Sync + 'static,
    <CS as CommitmentScheme>::Proof: Serialize
        + for<'de> serde::Deserialize<'de>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug
        + Encode
        + Decode,
    V: Verifier<Commitment = CS::Commitment, Proof = CS::Proof>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug,
{
    let envelope = refresh_handoff_source(context_arc).await?;
    let (store, local_successor, workload) = {
        let context = context_arc.lock().await;
        let store = context
            .aft_quv_handoff_store
            .as_ref()
            .cloned()
            .ok_or_else(|| anyhow!("local process has no staged-successor handoff store"))?;
        let local_successor = context
            .aft_pq_local_account_id
            .ok_or_else(|| anyhow!("local process has no PQ successor identity"))?;
        (
            store,
            local_successor,
            context.view_resolver.workload_client().clone(),
        )
    };
    // The boundary is immutable historical data once its old-root QC has been
    // checked. Read it by exact height rather than requiring it to remain the
    // local tip: an overlapping successor may observe new-root descendants
    // before its own known-synchronous QUV operation finishes. Those
    // descendants are not authority for this install; the fresh QUV operation
    // below remains mandatory.
    let block = workload
        .get_block_by_height(envelope.handoff.state_height)
        .await?
        .ok_or_else(|| anyhow!("QUV handoff boundary block is unavailable"))?;
    require_exact_handoff_boundary(&block, &envelope, "local historical executed state")?;
    let observed_height = block.header.height;
    let observed_hash: [u8; 32] = block
        .header
        .hash()
        .map_err(|error| anyhow!(error.to_string()))?
        .try_into()
        .map_err(|_| anyhow!("committed QUV handoff block hash is not 32 bytes"))?;
    let observed_root = block.header.state_root.0.clone();
    // Keep the explicit values bound into the durable install even though the
    // exact-boundary helper above already checked them.
    let successor_root = canonical_validator_set_hash(&envelope.handoff.successor_set)
        .map_err(anyhow::Error::msg)?;
    if store.lock().await.permits_exact_activation(
        &envelope,
        local_successor,
        observed_hash,
        &observed_root,
    ) {
        return Ok(HandoffInstallOutcome::ExistingGate(successor_root));
    }
    let mut nonce = [0_u8; 32];
    OsRng.fill_bytes(&mut nonce);
    let request = QuvPushQueryV0 {
        verifier_nonce: nonce,
        candidate: envelope.candidate.clone(),
    };
    let authorization = begin_online_authorization(context_arc, request)
        .await?
        .await
        .map_err(|_| anyhow!("QUV handoff operation completion was dropped"))??;
    let handoff = envelope.handoff;
    let store = store.lock_owned().await;
    tokio::task::spawn_blocking(move || {
        let mut store = store;
        store.install(
            authorization,
            handoff,
            local_successor,
            observed_height,
            observed_hash,
            &observed_root,
        )
    })
    .await
    .map_err(|error| anyhow!("QUV handoff install task failed: {error}"))?
    .map_err(anyhow::Error::new)
    .map(HandoffInstallOutcome::FreshLiveInstall)
}

async fn activate_installed_handoff<CS, ST, CE, V>(
    context_arc: &Arc<Mutex<MainLoopContext<CS, ST, CE, V>>>,
    envelope: &QuvConfigurationHandoffEnvelopeV0,
    successor_root: [u8; 32],
    recovery_from_gate: bool,
) -> Result<()>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + Debug
        + Clone,
    <CS as CommitmentScheme>::Commitment: Send + Sync + Debug,
    CE: ConsensusEngine<ChainTransaction> + Send + Sync + 'static,
    <CS as CommitmentScheme>::Proof: Serialize
        + for<'de> serde::Deserialize<'de>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug
        + Encode
        + Decode,
    V: Verifier<Commitment = CS::Commitment, Proof = CS::Proof>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug,
{
    let (
        workload,
        signer,
        local_account,
        local_peer,
        outbox_root,
        anchor_root,
        peers,
        commander,
        engine,
        safety_mode,
        store,
    ) = {
        let context = context_arc.lock().await;
        let local_account = context
            .aft_pq_local_account_id
            .ok_or_else(|| anyhow!("QUV successor has no local PQ identity"))?;
        let peers = context.peer_accounts_ref.lock().await.clone();
        (
            context.view_resolver.workload_client().clone(),
            context
                .pqc_signer
                .clone()
                .ok_or_else(|| anyhow!("QUV successor has no ML-DSA signer"))?,
            local_account,
            context.local_keypair.public().to_peer_id(),
            context.config.aft_pq_outbox_dir.clone(),
            context.config.aft_external_anchor_dir.clone(),
            peers,
            context.swarm_commander.clone(),
            context.consensus_engine_ref.clone(),
            context.config.aft_safety_mode,
            context
                .aft_quv_handoff_store
                .as_ref()
                .cloned()
                .ok_or_else(|| anyhow!("QUV successor has no durable handoff gate"))?,
        )
    };
    // The public/collapse status and orchestration cursor can intentionally
    // trail the workload's bounded projection. The raw execution cursor is a
    // readiness signal only; authority still requires the exact boundary
    // bytes, old-root QC, and process-local QUV install gate below.
    let current_height = workload.get_execution_status().await?.height;
    if current_height < envelope.handoff.old_authority_expiry_height {
        return Err(anyhow!(
            "QUV successor activation has not reached the old-root expiry boundary: executed {current_height}, required {}",
            envelope.handoff.old_authority_expiry_height
        ));
    }
    let boundary = workload
        .get_block_by_height(envelope.handoff.old_authority_expiry_height)
        .await?
        .ok_or_else(|| anyhow!("canonical QUV handoff boundary is unavailable"))?;
    let observed_hash: [u8; 32] = boundary
        .header
        .hash()
        .map_err(|error| anyhow!(error.to_string()))?
        .try_into()
        .map_err(|_| anyhow!("QUV activation block hash is not 32 bytes"))?;
    let observed_root = boundary.header.state_root.0.clone();
    if boundary.header.height != envelope.handoff.state_height
        || observed_hash != envelope.handoff.state_block_hash
        || observed_root != envelope.handoff.state_root
        || boundary.header.parent_qc.height.saturating_add(1) != boundary.header.height
        || boundary.header.parent_qc.block_hash != boundary.header.parent_hash
        || current_height.saturating_add(1) < envelope.handoff.activation_height
    {
        return Err(anyhow!(
            "canonical QUV handoff boundary differs from the locally installed source"
        ));
    }
    if !store.lock().await.permits_exact_activation(
        envelope,
        local_account,
        observed_hash,
        &observed_root,
    ) {
        return Err(anyhow!(
            "QUV successor activation lacks the exact local live-install gate"
        ));
    }

    {
        let mut context = context_arc.lock().await;
        if context
            .last_executed_block
            .as_ref()
            .map(|block| block.header.height < boundary.header.height)
            .unwrap_or(true)
        {
            context.last_executed_block = Some(boundary.clone());
        }
    }

    if !recovery_from_gate {
        // Authenticate the old-root boundary before using its rooted execution
        // journal to close the local consequence gap. Workload synchronization
        // supplies bytes, never admission authority.
        let mut engine = engine.lock().await;
        if !engine.observe_committed_block(&boundary.header, None) {
            return Err(anyhow!(
                "consensus engine refused the QUV boundary header continuity hint"
            ));
        }
        engine
            .handle_quorum_certificate(envelope.handoff.boundary_qc.clone())
            .await
            .map_err(|error| anyhow!(error.to_string()))?;
    }

    {
        // A successor is not allowed to install new ordering authority while
        // its consequence spine is behind the native finality floor of the
        // exact QUV boundary. The boundary QC commits its predecessor under
        // the two-chain rule; QUV separately binds the exact boundary that the
        // successor must extend. Recovery is capped at that predecessor so a
        // successor-certified descendant cannot be interpreted under the
        // retiring configuration.
        let required_admitted_height = envelope.handoff.state_height.saturating_sub(1);
        let mut context = context_arc.lock().await;
        super::runtime_finality::recover_workload_gap_through(
            &mut context,
            required_admitted_height,
        )
        .await?;
        let admitted = context
            .runtime_finality
            .lock()
            .await
            .last_admitted_block()?;
        let admitted_height = admitted
            .as_ref()
            .map(|block| block.header.height)
            .unwrap_or(0);
        if admitted_height < required_admitted_height {
            return Err(anyhow!(
                "Agentgres consequence spine has not admitted the QUV boundary predecessor"
            ));
        }
        if admitted_height == required_admitted_height && required_admitted_height > 0 {
            let admitted_hash = admitted
                .as_ref()
                .ok_or_else(|| anyhow!("QUV predecessor admission lost its staged block"))?
                .header
                .hash()
                .map_err(|error| anyhow!(error.to_string()))?;
            if admitted_hash.as_slice() != boundary.header.parent_hash {
                return Err(anyhow!(
                    "Agentgres consequence spine admitted a different QUV boundary predecessor"
                ));
            }
        } else if admitted_height == 0 && boundary.header.parent_hash != [0_u8; 32] {
            return Err(anyhow!(
                "genesis QUV boundary does not extend the Agentgres genesis head"
            ));
        }
    }

    let successor = &envelope.handoff.successor_set;
    let desired = super::consensus::build_aft_pq_channel_configuration(
        successor,
        envelope.handoff.activation_height,
        envelope.handoff.network_id,
        local_peer,
        Some(&signer),
        outbox_root.as_deref(),
    )?
    .ok_or_else(|| anyhow!("QUV successor configuration is not uniformly ML-DSA"))?;
    if desired.local.configuration_hash != successor_root
        || desired.local.account_id != local_account
    {
        return Err(anyhow!(
            "QUV successor configuration changed during activation"
        ));
    }

    let mut registry = ioi_consensus::aft::authenticated_quorum::ValidatorKeyRegistry::new();
    for validator in &successor.validators {
        let key = [
            ioi_types::keys::ACCOUNT_ID_TO_PUBKEY_PREFIX,
            validator.account_id.as_ref(),
        ]
        .concat();
        let public_key = workload
            .query_raw_state(&key)
            .await?
            .ok_or_else(|| anyhow!("canonical successor ML-DSA key is missing"))?;
        let derived = ioi_types::app::account_id_from_key_material(
            ioi_types::app::SignatureSuite::ML_DSA_44,
            &public_key,
        )
        .map_err(anyhow::Error::msg)?;
        if derived != validator.consensus_key.public_key_hash {
            return Err(anyhow!("canonical successor ML-DSA key was substituted"));
        }
        registry
            .learn_raw_public_key(ioi_types::app::SignatureSuite::ML_DSA_44, &public_key)
            .map_err(|error| anyhow!(error.to_string()))?;
    }

    let custody_key = super::consensus::derive_aft_async_custody_key(
        &signer,
        envelope.handoff.network_id,
        successor_root,
        local_account,
    )?;
    let paths = super::consensus::aft_async_storage_paths(
        outbox_root.as_deref(),
        anchor_root.as_deref(),
        successor_root,
        local_account,
        envelope.handoff.activation_height,
    )?;
    let signing_fence = ioi_consensus::aft::hash_async::DurableCrossPathSigningFence::open(
        &paths.signing_fence_state,
        &paths.signing_fence_anchor,
        ioi_types::app::AftFallbackScopeV1 {
            network_id: envelope.handoff.network_id,
            configuration_hash: successor_root,
            epoch: successor.effective_from_height,
        },
        local_account,
        &custody_key,
    )
    .map_err(anyhow::Error::msg)?;
    let (provisioning_root, domains) = {
        let context = context_arc.lock().await;
        (
            member_provisioning_root(
                envelope.handoff.network_id,
                successor_root,
                &context.config.aft_quv_domain_policies,
            )?,
            member_provisioned_domains(
                envelope.handoff.network_id,
                successor_root,
                &context.config.aft_quv_domain_policies,
            )?,
        )
    };
    let member = ioi_consensus::aft::query_unanimity::DurableQuvMemberV0::open(
        &paths.quv_member_state,
        &paths.quv_member_anchor,
        *custody_key,
        provisioning_root,
        domains,
    )?;
    {
        let mut engine = engine.lock().await;
        // Hydrate the successor set before opening its scoped fallback
        // journal. Journal admission deliberately validates the requested
        // scope against the latest rooted effective set; doing these in the
        // opposite order compares the successor scope with the old-root set
        // and makes every otherwise valid live handoff fail closed.
        if !engine.observe_validator_sets(
            envelope.handoff.activation_height,
            &ioi_types::app::ValidatorSetsV1 {
                current: successor.clone(),
                next: None,
            },
        ) {
            return Err(anyhow!(
                "consensus engine refused the installed QUV successor set"
            ));
        }
        if matches!(safety_mode, AftSafetyMode::ClassicBft) {
            let fallback = super::consensus::aft_fallback_journal_path(
                outbox_root.as_deref(),
                successor_root,
                local_account,
            )?;
            engine
                .configure_fallback_journal(
                    ioi_types::app::AftFallbackScopeV1 {
                        network_id: envelope.handoff.network_id,
                        configuration_hash: successor_root,
                        epoch: successor.effective_from_height,
                    },
                    &fallback,
                )
                .map_err(|error| anyhow!(error.to_string()))?;
        }
    }
    let enrollments = peers
        .into_iter()
        .filter_map(|(peer_id, account_id)| {
            (account_id != local_account).then(|| {
                desired
                    .peer_keys
                    .get(&account_id)
                    .copied()
                    .map(|identity_key_hash| PqPeerEnrollment {
                        peer_id,
                        account_id,
                        identity_key_hash,
                    })
            })
        })
        .flatten()
        .collect();
    let (configured, configured_rx) = oneshot::channel();
    commander
        .send(SwarmCommand::ConfigurePqChannels {
            config: desired.local,
            enrollments,
            handoff_only: false,
            response: configured,
        })
        .await
        .map_err(|error| anyhow!("failed to queue QUV successor activation: {error}"))?;
    configured_rx
        .await
        .map_err(|_| anyhow!("QUV successor activation acknowledgement was dropped"))?
        .map_err(anyhow::Error::msg)?;

    let mut context = context_arc.lock().await;
    context.local_validator_account_id = Some(local_account);
    context.aft_pq_configuration_hash = Some(successor_root);
    context.aft_pq_peer_keys = Some(desired.peer_keys);
    context.aft_pq_handoff_only_accounts.clear();
    context.aft_async_membership = Some((successor.clone(), registry));
    context.aft_async_custody_key = Some(custody_key);
    context.aft_cross_path_signing_fence = Some(Arc::new(std::sync::Mutex::new(signing_fence)));
    context.aft_quv_member = Some(Arc::new(Mutex::new(member)));
    context.aft_quv_preparation_notify.notify_one();
    context.aft_quv_staged_successor = None;
    Ok(())
}

/// Retry the live handoff only while the successor holds the exact signed
/// state block as its local executed boundary. That copy supplies state, not
/// authority: every correct old member separately requires the same block at
/// its committed boundary before replying to the fresh operation. Once the
/// successor tip advances, only recovery from the durable local install gate
/// is permitted; a fresh authorization is never retroactively created.
/// Old-only members do not run this task.
pub(crate) async fn run_preparation_worker<CS, ST, CE, V>(
    context_arc: Arc<Mutex<MainLoopContext<CS, ST, CE, V>>>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + Debug
        + Clone,
    <CS as CommitmentScheme>::Commitment: Send + Sync + Debug,
    CE: ConsensusEngine<ChainTransaction> + Send + Sync + 'static,
    <CS as CommitmentScheme>::Proof: Serialize
        + for<'de> serde::Deserialize<'de>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug
        + Encode
        + Decode,
    V: Verifier<Commitment = CS::Commitment, Proof = CS::Proof>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug,
{
    let notify = {
        let context = context_arc.lock().await;
        if !context.config.aft_quv_domain_policies.iter().any(|policy| {
            matches!(
                policy.bootstrap,
                ioi_types::app::QuvDomainBootstrapV0::Fixed { .. }
            )
        }) {
            return;
        }
        context.aft_quv_preparation_notify.clone()
    };
    let mut cursor = None;
    loop {
        if *shutdown.borrow() {
            return;
        }
        let mut visited = BTreeSet::new();
        loop {
            let store = {
                let context = context_arc.lock().await;
                context.aft_quv_member.clone()
            };
            let Some(store) = store else {
                break;
            };
            let store = store.lock_owned().await;
            let selection =
                tokio::task::spawn_blocking(move || store.next_preparation_candidate(cursor)).await;
            let candidate = match selection {
                Ok(Ok(Some(candidate))) => candidate,
                Ok(Ok(None)) => break,
                error => {
                    tracing::warn!(target: "quv", ?error, "QUV preparation selection refused");
                    break;
                }
            };
            let domain = candidate.slot.domain_id;
            if !visited.insert(domain) {
                break;
            }
            cursor = Some(domain);
            let mut nonce = [0; 32];
            OsRng.fill_bytes(&mut nonce);
            let request = QuvPushQueryV0 {
                verifier_nonce: nonce,
                candidate,
            };
            match begin_authorization(&context_arc, request, true).await {
                Ok(result) => {
                    tokio::select! {
                        outcome = result => {
                            tracing::debug!(target: "quv", event = "preparation_finished", nonce = %hex::encode(nonce), domain = %hex::encode(domain), accepted = matches!(outcome, Ok(Ok(_))));
                        }
                        _ = shutdown.changed() => return,
                    }
                    visited.clear();
                }
                Err(error) => {
                    tracing::debug!(target: "quv", event = "preparation_refused", domain = %hex::encode(domain), %error)
                }
            }
            if *shutdown.borrow() {
                return;
            }
        }
        tokio::select! {
            _ = notify.notified() => {},
            _ = shutdown.changed() => return,
        }
    }
}

pub(crate) async fn run_handoff_coordinator<CS, ST, CE, V>(
    context_arc: Arc<Mutex<MainLoopContext<CS, ST, CE, V>>>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + Debug
        + Clone,
    <CS as CommitmentScheme>::Commitment: Send + Sync + Debug,
    CE: ConsensusEngine<ChainTransaction> + Send + Sync + 'static,
    <CS as CommitmentScheme>::Proof: Serialize
        + for<'de> serde::Deserialize<'de>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug
        + Encode
        + Decode,
    V: Verifier<Commitment = CS::Commitment, Proof = CS::Proof>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug,
{
    let (enabled, recovered_envelope) = {
        let context = context_arc.lock().await;
        (
            context.aft_quv_handoff_store.is_some()
                && context.config.aft_quv_handoff_source.is_some(),
            context.aft_quv_handoff_envelope.clone(),
        )
    };
    if !enabled {
        return;
    }
    // A restart that already exact-matched a rollback-anchored local install
    // gate must consume only that gate. It never refreshes source bytes and
    // never re-runs QUV against an expired old root. Activation is retried,
    // however, because the process may have restarted before the exact
    // boundary bytes reached its workload.
    let recovered = match recovered_envelope {
        Some(envelope) => {
            let successor_root = match canonical_validator_set_hash(&envelope.handoff.successor_set)
            {
                Ok(root) => root,
                Err(error) => {
                    tracing::error!(target: "quv", %error, "Recovered QUV successor root is invalid; authority remains disabled");
                    return;
                }
            };
            Some((envelope, successor_root))
        }
        None => None,
    };
    let mut interval = tokio::time::interval(Duration::from_millis(250));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut boundary_pull_not_before = Instant::now();
    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    return;
                }
            }
            _ = interval.tick() => {
                let (envelope, successor_root, recovery_from_gate) = if let Some((envelope, successor_root)) = recovered.as_ref() {
                    (envelope.clone(), *successor_root, true)
                } else {
                    let envelope = match refresh_handoff_source(&context_arc).await {
                        Ok(source) => source,
                        Err(_) => continue,
                    };
                    let successor_root = match canonical_validator_set_hash(&envelope.handoff.successor_set) {
                        Ok(root) => root,
                        Err(error) => {
                            tracing::error!(target: "quv", %error, "Canonical QUV successor became invalid; authority remains disabled");
                            return;
                        }
                    };
                    (envelope, successor_root, false)
                };
                let target_height = envelope.handoff.state_height;
                let (tracked_height, sync_floor, commander, peer_accounts, workload) = {
                    let context = context_arc.lock().await;
                    (
                        context.last_executed_block.as_ref().map(|block| block.header.height).unwrap_or(0),
                        super::sync::agentgres_sync_floor(&context).await,
                        context.swarm_commander.clone(),
                        Arc::clone(&context.peer_accounts_ref),
                        context.view_resolver.workload_client().clone(),
                    )
                };
                let observed_height = workload
                    .get_execution_status()
                    .await
                    .map(|status| status.height)
                    .unwrap_or(tracked_height)
                    .max(tracked_height);
                if observed_height < target_height {
                    // Ordinary status is deliberately demoted to the
                    // Agentgres-admitted floor. A pre-authority successor that
                    // missed the boundary relay must therefore pull the exact
                    // QUV target explicitly instead of waiting for a peer to
                    // advertise not-yet-two-chain-final workload height. The
                    // response still grants no authority: activation below
                    // checks the exact source hash/root, old-root QC, local
                    // QUV gate, and consequence predecessor independently.
                    if Instant::now() >= boundary_pull_not_before {
                        boundary_pull_not_before = Instant::now() + Duration::from_secs(1);
                        let Some(sync_floor) = sync_floor else {
                            continue;
                        };
                        let peers = peer_accounts.lock().await.keys().copied().collect::<Vec<_>>();
                        let max_blocks = target_height
                            .saturating_sub(sync_floor)
                            .min(u64::from(super::sync::sync_batch_max_blocks()))
                            as u32;
                        for peer in peers {
                            let _ = commander
                                .send(SwarmCommand::SendBlocksRequest {
                                    peer,
                                    since: sync_floor,
                                    max_blocks,
                                    max_bytes: super::sync::sync_batch_max_bytes(),
                                })
                                .await;
                        }
                    }
                    continue;
                }
                if recovery_from_gate {
                    match activate_installed_handoff(
                        &context_arc,
                        &envelope,
                        successor_root,
                        true,
                    )
                    .await
                    {
                        Ok(()) => {
                            tracing::info!(target: "quv", successor_root = %hex::encode(successor_root), "Recovered QUV successor authority from its durable local install gate");
                            return;
                        }
                        Err(error) => {
                            tracing::warn!(target: "quv", %error, "Recovered QUV successor gate is not yet activatable; authority remains disabled");
                            continue;
                        }
                    }
                }
                if observed_height >= target_height {
                    match activate_installed_handoff(
                        &context_arc,
                        &envelope,
                        successor_root,
                        false,
                    )
                    .await
                    {
                        Ok(()) => {
                            tracing::info!(target: "quv", successor_root = %hex::encode(successor_root), "Recovered QUV successor authority from its durable local install gate");
                            return;
                        }
                        Err(_) => {
                            // An uninstalled live process may still execute its
                            // own old-root operation after observing successor
                            // descendants. This is required for overlapping
                            // roots, where other successors can form an
                            // ordering quorum first. Post-restart recovery took
                            // the branch above and never re-queries.
                        }
                    }
                }
                match authorize_and_install_handoff(&context_arc).await {
                    Ok(outcome) => {
                        let installed_root = outcome.configuration_root();
                        if installed_root != successor_root {
                            tracing::error!(target: "quv", "Installed QUV handoff root differs from the canonical successor; authority remains disabled");
                            return;
                        }
                        match activate_installed_handoff(
                            &context_arc,
                            &envelope,
                            successor_root,
                            false,
                        )
                        .await
                        {
                            Ok(()) => {
                                match outcome {
                                    HandoffInstallOutcome::ExistingGate(_) => {
                                        tracing::info!(target: "quv", successor_root = %hex::encode(successor_root), "Recovered QUV successor authority from its durable local install gate");
                                    }
                                    HandoffInstallOutcome::FreshLiveInstall(_) => {
                                        tracing::info!(target: "quv", successor_root = %hex::encode(successor_root), "Activated successor from its local live old-root QUV install");
                                    }
                                }
                                return;
                            }
                            Err(error) => {
                                tracing::warn!(target: "quv", %error, "Installed QUV successor did not activate; retrying from the durable local gate");
                            }
                        }
                    }
                    Err(error) => {
                        tracing::warn!(target: "quv", %error, "QUV successor handoff attempt did not install; retrying while the exact state boundary remains current");
                    }
                }
            }
        }
    }
}

/// Process an authenticated member request and return the durable signed
/// reply. The caller is responsible for routing it to `requester` over the
/// strict PQ channel.
async fn process_push<CS, ST, CE, V>(
    context_arc: &Arc<Mutex<MainLoopContext<CS, ST, CE, V>>>,
    requester: AccountId,
    query: QuvPushQueryV0,
) -> Result<(AccountId, QuvReplyV0)>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + Debug
        + Clone,
    <CS as CommitmentScheme>::Commitment: Send + Sync + Debug,
    CE: ConsensusEngine<ChainTransaction> + Send + Sync + 'static,
    <CS as CommitmentScheme>::Proof: Serialize
        + for<'de> serde::Deserialize<'de>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug
        + Encode
        + Decode,
    V: Verifier<Commitment = CS::Commitment, Proof = CS::Proof>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug,
{
    let (
        member_store,
        set,
        keys,
        signer,
        member,
        network_id,
        activation_height,
        policy,
        handoff_boundary,
    ) = {
        let context = context_arc.lock().await;
        let (set, keys) = context
            .aft_async_membership
            .as_ref()
            .ok_or_else(|| anyhow!("QUV requires a rooted all-ML-DSA membership"))?;
        let rooted_member = set
            .validators
            .iter()
            .any(|validator| validator.account_id == requester);
        let staged_handoff_requester =
            context
                .aft_quv_staged_successor
                .as_ref()
                .is_some_and(|successor| {
                    successor
                        .validators
                        .iter()
                        .any(|validator| validator.account_id == requester)
                })
                && context
                    .aft_quv_handoff_envelope
                    .as_ref()
                    .is_some_and(|envelope| envelope.candidate == query.candidate);
        if !rooted_member && !staged_handoff_requester {
            return Err(anyhow!(
                "QUV requester is neither an old member nor a source-bound staged successor"
            ));
        }
        let policy = provisioned_policy(&context.config.aft_quv_domain_policies, &query)?.clone();
        let handoff_boundary = if matches!(
            policy.bootstrap,
            ioi_types::app::QuvDomainBootstrapV0::HandoffBoundary { .. }
        ) {
            let envelope = context
                .aft_quv_handoff_envelope
                .as_ref()
                .ok_or_else(|| {
                    anyhow!("QUV staged-successor request has no canonical handoff source")
                })?
                .clone();
            if envelope.candidate != query.candidate {
                return Err(anyhow!(
                    "QUV handoff query differs from the provisioned source"
                ));
            }
            let staged = context
                .aft_quv_staged_successor
                .as_ref()
                .ok_or_else(|| anyhow!("QUV old member has no rooted staged successor"))?
                .clone();
            Some((
                envelope,
                staged,
                context.view_resolver.workload_client().clone(),
                context.config.aft_safety_mode,
            ))
        } else {
            None
        };
        (
            context
                .aft_quv_member
                .as_ref()
                .cloned()
                .ok_or_else(|| anyhow!("QUV durable member state is disabled"))?,
            set.clone(),
            keys.clone(),
            context
                .pqc_signer
                .clone()
                .ok_or_else(|| anyhow!("QUV requires a local ML-DSA signer"))?,
            context
                .local_validator_account_id
                .ok_or_else(|| anyhow!("QUV local rooted member is unavailable"))?,
            context.genesis_hash,
            context
                .last_committed_block
                .as_ref()
                .map(|block| block.header.height.max(1))
                .unwrap_or(1),
            policy,
            handoff_boundary,
        )
    };

    require_qualified_membership(&policy, set.validators.len())?;

    if let Some((envelope, staged, workload, safety_mode)) = handoff_boundary {
        // A correct member need not have assembled or cached the aggregate QC
        // itself. Independently verify the source QC under the current old
        // root, then match it to this member's exact local executed boundary.
        // These checks validate the live request; the source alone still
        // cannot authorize the relying successor or advance a member head.
        validate_handoff_source(
            &envelope,
            &set,
            &staged,
            &keys,
            std::slice::from_ref(&policy),
            network_id,
            safety_mode,
        )?;
        if workload.get_execution_status().await?.height < envelope.handoff.state_height {
            return Err(anyhow!(
                "QUV old member has not executed the handoff boundary"
            ));
        }
        let executed = workload
            .get_block_by_height(envelope.handoff.state_height)
            .await?
            .ok_or_else(|| anyhow!("QUV old member lacks the local executed handoff boundary"))?;
        require_exact_handoff_boundary(&executed, &envelope, "old member local executed history")?;
        let certified = &envelope.handoff.boundary_qc;
        if certified.height != executed.header.height
            || certified.view != executed.header.view
            || certified.block_hash != envelope.handoff.state_block_hash
        {
            return Err(anyhow!(
                "QUV old member's verified QC does not certify the source-bound handoff state"
            ));
        }
    }

    // Tokio's mutex grants the single durable serializer in FIFO lock-request
    // order. Combined with one admitted request per authenticated account,
    // no member can place an unbounded prefix ahead of another member.
    tracing::debug!(target: "quv", event = "member_work_queued", nonce = %hex::encode(query.verifier_nonce), ?requester, ?member);
    let store = member_store.lock_owned().await;
    let result = tokio::task::spawn_blocking(move || {
        let validator = RootedQuvCandidateValidatorV0::new(
            &set,
            &keys,
            activation_height,
            network_id,
            provisioned_policy_root(&policy)?,
            policy.owner,
        )?;
        let signer = RuntimeQuvSignerV0 { member, signer };
        let mut store = store;
        let result = store.process_push(&query, &validator, &signer);
        tracing::debug!(target: "quv", event = "member_work_completed", nonce = %hex::encode(query.verifier_nonce), ?requester, ?member, succeeded = result.is_ok());
        result
    })
    .await
    .map_err(|error| anyhow!("QUV durable task failed: {error}"))?
    .map(|reply| (requester, reply))
    .map_err(anyhow::Error::new);
    context_arc
        .lock()
        .await
        .aft_quv_preparation_notify
        .notify_one();
    result
}

/// Admit at most one PUSHQUERY per authenticated rooted account and dispatch
/// durable work off the main network-event loop. The rooted configuration has
/// finite size, so Byzantine senders cannot create an unbounded work queue.
pub(super) async fn dispatch_push_query<CS, ST, CE, V>(
    context_arc: &Arc<Mutex<MainLoopContext<CS, ST, CE, V>>>,
    requester: AccountId,
    from: PeerId,
    query: QuvPushQueryV0,
) where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + Debug
        + Clone,
    <CS as CommitmentScheme>::Commitment: Send + Sync + Debug,
    CE: ConsensusEngine<ChainTransaction> + Send + Sync + 'static,
    <CS as CommitmentScheme>::Proof: Serialize
        + for<'de> serde::Deserialize<'de>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug
        + Encode
        + Decode,
    V: Verifier<Commitment = CS::Commitment, Proof = CS::Proof>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug,
{
    let (rooted_requester, staged_requester, commander) = {
        let context = context_arc.lock().await;
        (
            context
                .aft_async_membership
                .as_ref()
                .is_some_and(|(set, _)| {
                    set.validators
                        .iter()
                        .any(|member| member.account_id == requester)
                }),
            context
                .aft_quv_staged_successor
                .as_ref()
                .is_some_and(|set| {
                    set.validators
                        .iter()
                        .any(|member| member.account_id == requester)
                }),
            context.quv_swarm_commander.clone(),
        )
    };
    let source_bound_successor = if staged_requester {
        match refresh_handoff_source(context_arc).await {
            Ok(envelope) => envelope.candidate == query.candidate,
            Err(error) => {
                tracing::warn!(target: "quv", %from, %error, "Refused staged-successor QUV request without a valid canonical handoff source");
                false
            }
        }
    } else {
        false
    };
    if !rooted_requester && !source_bound_successor {
        tracing::warn!(
            target: "quv",
            %from,
            requester = %hex::encode(requester.as_ref()),
            "Dropped QUV PUSHQUERY from an authenticated account outside admitted old/handoff membership"
        );
        let _ = commander
            .send(SwarmCommand::CompleteQuvPush {
                requester,
                nonce: query.verifier_nonce,
            })
            .await;
        return;
    }
    {
        let mut context = context_arc.lock().await;
        if !context.aft_quv_push_inflight.insert(requester) {
            tracing::warn!(
                target: "quv",
                %from,
                requester = %hex::encode(requester.as_ref()),
                "Dropped QUV PUSHQUERY because this authenticated account already has durable work in flight"
            );
            return;
        }
    }
    let context = Arc::clone(context_arc);
    let nonce = query.verifier_nonce;
    tokio::spawn(async move {
        handle_push_query(&context, requester, from, query).await;
        let commander = {
            let mut locked = context.lock().await;
            locked.aft_quv_push_inflight.remove(&requester);
            locked.quv_swarm_commander.clone()
        };
        let _ = commander
            .send(SwarmCommand::CompleteQuvPush { requester, nonce })
            .await;
    });
}

/// Handle one admitted remote PUSHQUERY. Malformed or unprovisioned requests
/// fail closed and emit no reply.
async fn handle_push_query<CS, ST, CE, V>(
    context_arc: &Arc<Mutex<MainLoopContext<CS, ST, CE, V>>>,
    requester: AccountId,
    from: PeerId,
    query: QuvPushQueryV0,
) where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + Debug
        + Clone,
    <CS as CommitmentScheme>::Commitment: Send + Sync + Debug,
    CE: ConsensusEngine<ChainTransaction> + Send + Sync + 'static,
    <CS as CommitmentScheme>::Proof: Serialize
        + for<'de> serde::Deserialize<'de>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug
        + Encode
        + Decode,
    V: Verifier<Commitment = CS::Commitment, Proof = CS::Proof>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug,
{
    match process_push(context_arc, requester, query).await {
        Ok((recipient, reply)) => match codec::to_bytes_canonical(&reply) {
            Ok(data) => {
                let commander = context_arc.lock().await.quv_swarm_commander.clone();
                if let Err(error) = commander
                    .send(SwarmCommand::QueueQuvReply { recipient, data })
                    .await
                {
                    tracing::warn!(target: "quv", %from, %error, "Failed to queue durable QUV reply");
                }
            }
            Err(error) => {
                tracing::warn!(target: "quv", %from, %error, "Failed to encode durable QUV reply")
            }
        },
        Err(error) => {
            tracing::warn!(target: "quv", %from, %error, "Refused QUV PUSHQUERY")
        }
    }
}

/// Route an authenticated reply only into its live nonce-bound operation.
/// Transport identity must match the signed member identity before the reply
/// is retained for final verification.
pub(super) async fn handle_reply<CS, ST, CE, V>(
    context_arc: &Arc<Mutex<MainLoopContext<CS, ST, CE, V>>>,
    authenticated_member: AccountId,
    from: PeerId,
    reply: QuvReplyV0,
) where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + Debug
        + Clone,
    <CS as CommitmentScheme>::Commitment: Send + Sync + Debug,
    CE: ConsensusEngine<ChainTransaction> + Send + Sync + 'static,
    <CS as CommitmentScheme>::Proof: Serialize
        + for<'de> serde::Deserialize<'de>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug
        + Encode
        + Decode,
{
    if reply.member != authenticated_member {
        tracing::warn!(
            target: "quv",
            %from,
            authenticated = %hex::encode(authenticated_member.as_ref()),
            claimed = %hex::encode(reply.member.as_ref()),
            "Refused QUV reply whose signed member differs from its PQ channel identity"
        );
        return;
    }
    let nonce = reply.verifier_nonce;
    let mut context = context_arc.lock().await;
    tracing::debug!(target: "quv", event = "reply_routed", nonce = %hex::encode(nonce), ?authenticated_member, live_operation = context.aft_quv_operations.contains_key(&nonce));
    let Some(pending) = context.aft_quv_operations.get_mut(&nonce) else {
        tracing::warn!(target: "quv", %from, "Dropped QUV reply with no live nonce-bound operation");
        return;
    };
    pending.operation.observe_reply(reply);
}

/// Start the executor-owned online operation. The returned single-use result
/// is produced only after the complete provisioned decision interval. A send
/// failure to any configured member aborts the operation; it never silently
/// narrows the queried membership.
pub(crate) async fn begin_online_authorization<CS, ST, CE, V>(
    context_arc: &Arc<Mutex<MainLoopContext<CS, ST, CE, V>>>,
    request: QuvPushQueryV0,
) -> Result<oneshot::Receiver<std::result::Result<QuvOnlineAuthorizationV0, anyhow::Error>>>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + Debug
        + Clone,
    <CS as CommitmentScheme>::Commitment: Send + Sync + Debug,
    CE: ConsensusEngine<ChainTransaction> + Send + Sync + 'static,
    <CS as CommitmentScheme>::Proof: Serialize
        + for<'de> serde::Deserialize<'de>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug
        + Encode
        + Decode,
    V: Verifier<Commitment = CS::Commitment, Proof = CS::Proof>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug,
{
    begin_authorization(context_arc, request, false).await
}

async fn begin_authorization<CS, ST, CE, V>(
    context_arc: &Arc<Mutex<MainLoopContext<CS, ST, CE, V>>>,
    request: QuvPushQueryV0,
    independent_preparation: bool,
) -> Result<oneshot::Receiver<std::result::Result<QuvOnlineAuthorizationV0, anyhow::Error>>>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + Debug
        + Clone,
    <CS as CommitmentScheme>::Commitment: Send + Sync + Debug,
    CE: ConsensusEngine<ChainTransaction> + Send + Sync + 'static,
    <CS as CommitmentScheme>::Proof: Serialize
        + for<'de> serde::Deserialize<'de>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug
        + Encode
        + Decode,
    V: Verifier<Commitment = CS::Commitment, Proof = CS::Proof>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug,
{
    // Waiting capacity is bounded per enrolled domain; preparation has one
    // lifecycle caller. Every root/head check below is repeated after waiting.
    let gate = {
        let context = context_arc.lock().await;
        let (set, keys) = context
            .aft_async_membership
            .as_ref()
            .ok_or_else(|| anyhow!("QUV requires a rooted all-ML-DSA membership"))?;
        let policy = provisioned_policy(&context.config.aft_quv_domain_policies, &request)?;
        require_qualified_membership(policy, set.validators.len())?;
        let height = context
            .last_committed_block
            .as_ref()
            .map(|block| block.header.height.max(1))
            .unwrap_or(1);
        RootedQuvCandidateValidatorV0::new(
            set,
            keys,
            height,
            context.genesis_hash,
            provisioned_policy_root(policy)?,
            policy.owner,
        )?
        .validate_candidate(&request.candidate)?;
        context.aft_quv_admission.clone()
    };
    let admission = if independent_preparation {
        gate.preparation().await?
    } else {
        gate.foreground(request.candidate.slot.domain_id).await?
    };
    let service_started = Instant::now();
    let service_deadline = if independent_preparation {
        let context = context_arc.lock().await;
        let policy = provisioned_policy(&context.config.aft_quv_domain_policies, &request)?;
        let ioi_types::app::QuvPreparationPolicyV0::Independent { service_millis, .. } =
            policy.preparation
        else {
            return Err(anyhow!(
                "QUV preparation requires an independent service policy"
            ));
        };
        Some(
            service_started
                .checked_add(Duration::from_millis(service_millis))
                .ok_or_else(|| anyhow!("QUV preparation service deadline overflow"))?,
        )
    } else {
        None
    };
    let nonce = request.verifier_nonce;
    let admitted = begin_admitted_authorization(
        context_arc,
        request,
        independent_preparation,
        admission,
        service_deadline,
    );
    match service_deadline {
        Some(deadline) => match tokio::time::timeout_at(deadline.into(), admitted).await {
            Ok(result) if Instant::now() < deadline => result,
            _ => {
                tracing::warn!(target: "quv", event = "preparation_service_expired", nonce = %hex::encode(nonce), phase = "startup_dispatch");
                abort_operation(
                    context_arc,
                    nonce,
                    "QUV preparation active service deadline exceeded".into(),
                )
                .await;
                Err(anyhow!("QUV preparation active service deadline exceeded"))
            }
        },
        None => admitted.await,
    }
}

async fn begin_admitted_authorization<CS, ST, CE, V>(
    context_arc: &Arc<Mutex<MainLoopContext<CS, ST, CE, V>>>,
    request: QuvPushQueryV0,
    independent_preparation: bool,
    admission: OwnedSemaphorePermit,
    service_deadline: Option<Instant>,
) -> Result<oneshot::Receiver<std::result::Result<QuvOnlineAuthorizationV0, anyhow::Error>>>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + Debug
        + Clone,
    <CS as CommitmentScheme>::Commitment: Send + Sync + Debug,
    CE: ConsensusEngine<ChainTransaction> + Send + Sync + 'static,
    <CS as CommitmentScheme>::Proof: Serialize
        + for<'de> serde::Deserialize<'de>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug
        + Encode
        + Decode,
    V: Verifier<Commitment = CS::Commitment, Proof = CS::Proof>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug,
{
    let nonce = request.verifier_nonce;
    let (members, local_endpoint, self_delivers, policy, commander, preparation_store) = {
        let context = context_arc.lock().await;
        if context.aft_quv_operations.contains_key(&nonce) {
            return Err(anyhow!("QUV verifier nonce is already live"));
        }
        let (set, keys) = context
            .aft_async_membership
            .as_ref()
            .ok_or_else(|| anyhow!("QUV requires a rooted all-ML-DSA membership"))?;
        let policy = provisioned_policy(&context.config.aft_quv_domain_policies, &request)?.clone();
        if matches!(
            policy.bootstrap,
            ioi_types::app::QuvDomainBootstrapV0::HandoffBoundary { .. }
        ) && !context
            .aft_quv_handoff_envelope
            .as_ref()
            .is_some_and(|envelope| envelope.candidate == request.candidate)
        {
            return Err(anyhow!(
                "QUV handoff executor requires the exact provisioned source"
            ));
        }
        require_qualified_membership(&policy, set.validators.len())?;
        let activation_height = context
            .last_committed_block
            .as_ref()
            .map(|block| block.header.height.max(1))
            .unwrap_or(1);
        RootedQuvCandidateValidatorV0::new(
            set,
            keys,
            activation_height,
            context.genesis_hash,
            provisioned_policy_root(&policy)?,
            policy.owner,
        )?
        .validate_candidate(&request.candidate)?;
        if matches!(
            policy.bootstrap,
            ioi_types::app::QuvDomainBootstrapV0::Fixed { .. }
        ) {
            let store = context
                .aft_quv_member
                .as_ref()
                .ok_or_else(|| anyhow!("QUV fixed-domain executor has no local member history"))?;
            store
                .lock()
                .await
                .check_expected_slot(&request.candidate.slot)?;
        }
        let members = set
            .validators
            .iter()
            .map(|member| member.account_id)
            .collect::<BTreeSet<_>>();
        let local_endpoint = context
            .aft_pq_local_account_id
            .ok_or_else(|| anyhow!("QUV local PQ endpoint is unavailable"))?;
        let self_delivers = members.contains(&local_endpoint);
        (
            members,
            local_endpoint,
            self_delivers,
            policy,
            context.quv_swarm_commander.clone(),
            context.aft_quv_member.clone(),
        )
    };

    let dispatch = QuvDispatchV0::new(
        members.clone(),
        Duration::from_millis(policy.delta_rt_millis),
    )?;
    finish_active_service(Ok(()), service_deadline, Instant::now())?;
    if independent_preparation {
        let candidate = request.candidate.clone();
        let reservation_policy = policy.clone();
        let reservation = async {
            let store =
                preparation_store.ok_or_else(|| anyhow!("QUV preparation has no local store"))?;
            let mut store = store.lock_owned().await;
            tokio::task::spawn_blocking(move || {
                if service_deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                    return Err(QuvError::ExpiredAuthorization);
                }
                store.reserve_preparation_attempt(&candidate, &reservation_policy)
            })
            .await
            .map_err(|error| anyhow!("QUV preparation reservation task failed: {error}"))?
            .map_err(anyhow::Error::new)
        }
        .await;
        match reservation {
            Ok(attempt) => {
                tracing::debug!(target: "quv", event = "preparation_attempt_reserved", nonce = %hex::encode(nonce), attempt)
            }
            Err(error) => {
                return Err(error);
            }
        }
    }

    // The verifier interval starts only after the isolated swarm lane has
    // opened a fresh reply-admission epoch. This prevents stale traffic or a
    // general-command backlog from consuming any part of Delta_rt.
    let (admission_ready, ready) = oneshot::channel();
    if let Err(error) = commander
        .send(SwarmCommand::BeginQuvOperation {
            nonce,
            response: admission_ready,
        })
        .await
    {
        return Err(anyhow!("QUV command lane is unavailable: {error}"));
    }
    if ready.await.is_err() {
        return Err(anyhow!(
            "QUV command lane closed before admission was ready"
        ));
    }

    let decision_interval = Duration::from_millis(policy.delta_rt_millis);
    let operation = match QuvOnlineOperationV0::start(
        request.clone(),
        members.clone(),
        decision_interval,
        Duration::from_millis(policy.continuation_millis),
    ) {
        Ok(operation) => operation,
        Err(error) => {
            let _ = commander
                .send(SwarmCommand::CompleteQuvOperation { nonce })
                .await;
            return Err(error.into());
        }
    };
    let (completion, receiver) = oneshot::channel();
    let inserted = {
        let mut context = context_arc.lock().await;
        match context.aft_quv_operations.entry(nonce) {
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert(PendingQuvOperationV0 {
                    admission,
                    dispatch,
                    service_deadline,
                    operation,
                    completion,
                });
                true
            }
            std::collections::hash_map::Entry::Occupied(_) => false,
        }
    };
    if !inserted {
        let _ = commander
            .send(SwarmCommand::CompleteQuvOperation { nonce })
            .await;
        return Err(anyhow!("QUV verifier nonce raced another operation"));
    }
    tracing::debug!(target: "quv", event = "operation_started", independent_preparation, nonce = %hex::encode(nonce), payload = %hex::encode(request.candidate.payload_hash), ?local_endpoint, local_account_hex = %hex::encode(local_endpoint.as_ref()), members = ?members, decision_millis = policy.delta_rt_millis);
    let context_for_deadline = Arc::clone(context_arc);
    tokio::spawn(async move {
        let wait = service_deadline.map_or(decision_interval, |deadline| {
            decision_interval.min(deadline.saturating_duration_since(Instant::now()))
        });
        tokio::time::sleep(wait).await;
        finish_operation(&context_for_deadline, nonce).await;
    });

    let data = match codec::to_bytes_canonical(&request) {
        Ok(data) => data,
        Err(error) => {
            abort_operation(context_arc, nonce, error).await;
            return Ok(receiver);
        }
    };
    for recipient in members
        .into_iter()
        .filter(|member| *member != local_endpoint)
    {
        let (queued, queue_result) = oneshot::channel();
        if let Err(error) = commander
            .send(SwarmCommand::QueueQuvPushQuery {
                recipient,
                data: data.clone(),
                response: queued,
            })
            .await
        {
            abort_operation(context_arc, nonce, error.to_string()).await;
            return Ok(receiver);
        }
        match queue_result.await {
            Ok(Ok(())) => {
                let mut context = context_arc.lock().await;
                let Some(pending) = context.aft_quv_operations.get_mut(&nonce) else {
                    return Ok(receiver);
                };
                if let Err(error) = pending
                    .dispatch
                    .record(recipient, pending.operation.elapsed())
                {
                    drop(context);
                    abort_operation(context_arc, nonce, error.to_string()).await;
                    return Ok(receiver);
                }
            }
            Ok(Err(error)) => {
                abort_operation(context_arc, nonce, error).await;
                return Ok(receiver);
            }
            Err(_) => {
                abort_operation(
                    context_arc,
                    nonce,
                    "QUV command lane closed before durable request admission".to_string(),
                )
                .await;
                return Ok(receiver);
            }
        }
    }

    if self_delivers {
        // An overlapping successor traverses the same local durable member
        // state machine after remote admission. A successor-only endpoint has
        // no old-root member state and therefore never manufactures a
        // loopback reply.
        match process_push(context_arc, local_endpoint, request.clone()).await {
            Ok((_, reply)) => {
                let mut context = context_arc.lock().await;
                if let Some(pending) = context.aft_quv_operations.get_mut(&nonce) {
                    pending.operation.observe_reply(reply);
                    if let Err(error) = pending
                        .dispatch
                        .record(local_endpoint, pending.operation.elapsed())
                    {
                        drop(context);
                        abort_operation(context_arc, nonce, error.to_string()).await;
                        return Ok(receiver);
                    }
                }
            }
            Err(error) => {
                abort_operation(context_arc, nonce, error.to_string()).await;
                return Ok(receiver);
            }
        }
    }

    Ok(receiver)
}

async fn abort_operation<CS, ST, CE, V>(
    context_arc: &Arc<Mutex<MainLoopContext<CS, ST, CE, V>>>,
    nonce: QuvNonce,
    error: String,
) where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + Debug
        + Clone,
    <CS as CommitmentScheme>::Commitment: Send + Sync + Debug,
    CE: ConsensusEngine<ChainTransaction> + Send + Sync + 'static,
    <CS as CommitmentScheme>::Proof: Serialize
        + for<'de> serde::Deserialize<'de>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug
        + Encode
        + Decode,
{
    let (pending, commander) = {
        let mut context = context_arc.lock().await;
        (
            context.aft_quv_operations.remove(&nonce),
            context.quv_swarm_commander.clone(),
        )
    };
    if let Err(error) = commander.try_send(SwarmCommand::CompleteQuvOperation { nonce }) {
        tracing::error!(target: "quv", %error, "QUV completion exceeded its reserved command-lane capacity");
    }
    if let Some(pending) = pending {
        drop(pending.admission);
        let _ = pending.completion.send(Err(anyhow!(error)));
        context_arc
            .lock()
            .await
            .aft_quv_preparation_notify
            .notify_one();
    }
}

async fn finish_operation<CS, ST, CE, V>(
    context_arc: &Arc<Mutex<MainLoopContext<CS, ST, CE, V>>>,
    nonce: QuvNonce,
) where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + Debug
        + Clone,
    <CS as CommitmentScheme>::Commitment: Send + Sync + Debug,
    CE: ConsensusEngine<ChainTransaction> + Send + Sync + 'static,
    <CS as CommitmentScheme>::Proof: Serialize
        + for<'de> serde::Deserialize<'de>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug
        + Encode
        + Decode,
{
    let (pending, rooted, activation_height, network_id, policy, member_store, commander) = {
        let mut context = context_arc.lock().await;
        let Some(pending) = context.aft_quv_operations.remove(&nonce) else {
            return;
        };
        // Keep local admission reserved until the accepted head is durable,
        // including when the result receiver has disappeared.
        let rooted = context.aft_async_membership.clone();
        let policy = provisioned_policy(
            &context.config.aft_quv_domain_policies,
            pending.operation.request(),
        )
        .cloned()
        .ok();
        (
            pending,
            rooted,
            context
                .last_committed_block
                .as_ref()
                .map(|block| block.header.height.max(1))
                .unwrap_or(1),
            context.genesis_hash,
            policy,
            context.aft_quv_member.clone(),
            context.quv_swarm_commander.clone(),
        )
    };
    let PendingQuvOperationV0 {
        admission,
        dispatch,
        service_deadline,
        operation,
        completion,
    } = pending;
    let advance_fixed = policy.as_ref().is_some_and(|policy| {
        matches!(
            policy.bootstrap,
            ioi_types::app::QuvDomainBootstrapV0::Fixed { .. }
        )
    });
    let outcome = dispatch.finish(|| -> Result<QuvOnlineAuthorizationV0> {
        let (set, keys) = rooted.ok_or_else(|| anyhow!("QUV rooted membership disappeared"))?;
        let policy = policy.ok_or_else(|| anyhow!("QUV provisioned policy disappeared"))?;
        let candidate_validator = RootedQuvCandidateValidatorV0::new(
            &set,
            &keys,
            activation_height,
            network_id,
            provisioned_policy_root(&policy)?,
            policy.owner,
        )?;
        let reply_verifier = RootedQuvReplyVerifierV0::new(&candidate_validator);
        let authorization = operation.finish(&candidate_validator, &reply_verifier)?;
        match service_deadline {
            Some(deadline) => authorization
                .with_expiry_cap(deadline)
                .map_err(anyhow::Error::new),
            None => Ok(authorization),
        }
    });
    let outcome = match outcome {
        Ok(authorization) if advance_fixed => match member_store {
            Some(store) => {
                let mut store = store.lock_owned().await;
                tokio::task::spawn_blocking(move || {
                    store.advance_accepted_history(&authorization)?;
                    Ok::<_, QuvError>(authorization)
                })
                .await
                .map_err(|error| anyhow!("QUV accepted-history task failed: {error}"))
                .and_then(|result| result.map_err(anyhow::Error::new))
            }
            None => Err(anyhow!(
                "QUV fixed-domain executor lost its local history store"
            )),
        },
        other => other,
    };
    {
        let context = context_arc.lock().await;
        if let Err(error) = commander.try_send(SwarmCommand::CompleteQuvOperation { nonce }) {
            tracing::error!(target: "quv", %error, "QUV completion exceeded its reserved command-lane capacity");
        }
        context.aft_quv_preparation_notify.notify_one();
    }
    // An already-started atomic storage write cannot be undone by timeout.
    // Report a service overrun as failure even if that write completed, and
    // never return an expired grant or count it as timely preparation.
    let completed_at = Instant::now();
    let service_budgeted = service_deadline.is_some();
    let service_budget_met = service_deadline.is_none_or(|deadline| completed_at < deadline);
    let outcome = finish_active_service(outcome, service_deadline, completed_at);
    if !service_budget_met {
        tracing::warn!(target: "quv", event = "preparation_service_expired", nonce = %hex::encode(nonce), phase = "finalization");
    }
    drop(admission);
    tracing::debug!(target: "quv", event = "operation_finished", service_budgeted, service_budget_met, nonce = %hex::encode(nonce), accepted = outcome.is_ok(), error = ?outcome.as_ref().err());
    let _ = completion.send(outcome);
}

#[cfg(test)]
mod tests {
    use super::*;
    use ioi_api::crypto::{SerializableKey, SigningKeyPair};
    use ioi_consensus::aft::authenticated_quorum::consensus_vote_signing_bytes;
    use ioi_consensus::aft::query_unanimity::{
        quv_candidate_authority_signing_bytes, quv_handoff_domain_id, quv_handoff_payload_hash,
    };
    use ioi_crypto::{security::SecurityLevel, sign::dilithium::MldsaScheme};
    use ioi_types::app::{
        account_id_from_key_material, ActiveKeyRecord, QuvAuthorityModeV0, QuvCandidateV0,
        QuvConfigurationHandoffV0, QuvSlotV0, SignatureSuite, ValidatorSetV1, ValidatorV1,
    };

    #[test]
    fn active_service_completion_never_reports_late_success() {
        let deadline = Instant::now();
        assert_eq!(
            finish_active_service(Ok(7), Some(deadline), deadline - Duration::from_nanos(1))
                .unwrap(),
            7
        );
        for observed in [deadline, deadline + Duration::from_nanos(1)] {
            assert!(finish_active_service(Ok(7), Some(deadline), observed).is_err());
        }
        assert_eq!(finish_active_service(Ok(7), None, deadline).unwrap(), 7);
        let error = finish_active_service::<()>(
            Err(anyhow!("live query refused")),
            Some(deadline),
            deadline - Duration::from_nanos(1),
        )
        .unwrap_err();
        assert_eq!(error.to_string(), "live query refused");
    }

    fn member(key_hash: [u8; 32], since_height: u64) -> ValidatorV1 {
        ValidatorV1 {
            account_id: AccountId(key_hash),
            weight: 1,
            consensus_key: ActiveKeyRecord {
                suite: SignatureSuite::ML_DSA_44,
                public_key_hash: key_hash,
                since_height,
            },
        }
    }

    #[test]
    fn provisioned_bootstrap_rejects_initial_coordinate_substitution() {
        use ioi_types::app::QuvDomainBootstrapV0 as Bootstrap;
        let mut policy = AftQuvDomainPolicyV0 {
            preparation: ioi_types::app::QuvPreparationPolicyV0::Independent {
                max_attempts_per_slot: 2,
                service_millis: (1_000 as u64).saturating_add(50 as u64),
                readiness_millis: 1_000_000,
            },
            domain_id: [7; 32],
            bootstrap: Bootstrap::Fixed {
                initial_slot: 9,
                predecessor: [77; 32],
            },
            authority_mode: QuvAuthorityModeV0::Unowned,
            owner: None,
            delta_rt_millis: 1_000,
            qualified_delta_rt_envelope_millis: 800,
            qualified_max_configured_members: 4,
            continuation_millis: 50,
        };
        let mut query = QuvPushQueryV0 {
            verifier_nonce: [1; 32],
            candidate: QuvCandidateV0 {
                slot: QuvSlotV0 {
                    configuration_root: [2; 32],
                    policy_root: provisioned_policy_root(&policy).unwrap(),
                    network_id: [3; 32],
                    domain_id: policy.domain_id,
                    slot: 9,
                    predecessor: [77; 32],
                    authority_mode: QuvAuthorityModeV0::Unowned,
                },
                payload_hash: [4; 32],
                authorizer: AccountId([5; 32]),
                authority_signature: Vec::new(),
            },
        };
        provisioned_policy(std::slice::from_ref(&policy), &query).unwrap();
        query.candidate.slot.predecessor = [78; 32];
        assert!(provisioned_policy(std::slice::from_ref(&policy), &query).is_err());
        query.candidate.slot.predecessor = [77; 32];
        query.candidate.slot.slot = 8;
        assert!(provisioned_policy(std::slice::from_ref(&policy), &query).is_err());
        policy.preparation = ioi_types::app::QuvPreparationPolicyV0::OneShot;
        policy.bootstrap = Bootstrap::HandoffBoundary {
            activation_height: 12,
        };
        policy.authority_mode = QuvAuthorityModeV0::Owned;
        policy.owner = Some(AccountId([5; 32]));
        query.candidate.slot.authority_mode = QuvAuthorityModeV0::Owned;
        query.candidate.slot.policy_root = provisioned_policy_root(&policy).unwrap();
        query.candidate.slot.slot = 12;
        provisioned_policy(std::slice::from_ref(&policy), &query).unwrap();
        for wrong_slot in [11, 13] {
            query.candidate.slot.slot = wrong_slot;
            assert!(provisioned_policy(std::slice::from_ref(&policy), &query).is_err());
        }
        // This helper checks bootstrap coordinates only. The production path
        // separately authenticates candidates and verifies the local boundary.
    }

    #[test]
    fn runtime_refuses_membership_above_qualified_envelope() {
        let policy = AftQuvDomainPolicyV0 {
            preparation: ioi_types::app::QuvPreparationPolicyV0::Independent {
                max_attempts_per_slot: 2,
                service_millis: (1_000 as u64).saturating_add(50 as u64),
                readiness_millis: 1_000_000,
            },
            bootstrap: ioi_types::app::QuvDomainBootstrapV0::Fixed {
                initial_slot: 1,
                predecessor: [77; 32],
            },
            domain_id: [7; 32],
            authority_mode: QuvAuthorityModeV0::Unowned,
            owner: None,
            delta_rt_millis: 1_000,
            qualified_delta_rt_envelope_millis: 800,
            qualified_max_configured_members: 4,
            continuation_millis: 50,
        };
        require_qualified_membership(&policy, 4).expect("qualified membership is admitted");
        assert!(require_qualified_membership(&policy, 5).is_err());
        assert!(require_qualified_membership(&policy, 0).is_err());
    }

    #[test]
    fn handoff_source_requires_old_owner_signature_and_exact_staged_set() {
        let owner_key = MldsaScheme::new(SecurityLevel::Level2)
            .generate_keypair()
            .unwrap();
        let owner_public = owner_key.public_key().to_bytes();
        let owner_hash =
            account_id_from_key_material(SignatureSuite::ML_DSA_44, &owner_public).unwrap();
        let owner = AccountId(owner_hash);
        let other_old_keys = (0..3)
            .map(|_| {
                MldsaScheme::new(SecurityLevel::Level2)
                    .generate_keypair()
                    .unwrap()
            })
            .collect::<Vec<_>>();
        let mut old_members = vec![member(owner_hash, 1)];
        old_members.extend(other_old_keys.iter().map(|key| {
            let hash = account_id_from_key_material(
                SignatureSuite::ML_DSA_44,
                &key.public_key().to_bytes(),
            )
            .unwrap();
            member(hash, 1)
        }));
        old_members.sort_by_key(|member| member.account_id);
        let old = ValidatorSetV1 {
            effective_from_height: 1,
            total_weight: 4,
            validators: old_members,
        };
        let mut successor_members = (0..2)
            .map(|_| {
                let key = MldsaScheme::new(SecurityLevel::Level2)
                    .generate_keypair()
                    .unwrap();
                let hash = account_id_from_key_material(
                    SignatureSuite::ML_DSA_44,
                    &key.public_key().to_bytes(),
                )
                .unwrap();
                member(hash, 8)
            })
            .collect::<Vec<_>>();
        successor_members.sort_by_key(|member| member.account_id);
        let successor = ValidatorSetV1 {
            effective_from_height: 8,
            total_weight: 2,
            validators: successor_members,
        };
        let network = [3; 32];
        let old_root = canonical_validator_set_hash(&old).unwrap();
        let successor_root = canonical_validator_set_hash(&successor).unwrap();
        let domain = quv_handoff_domain_id(network, old_root, successor_root, 8).unwrap();
        let policy = AftQuvDomainPolicyV0 {
            preparation: ioi_types::app::QuvPreparationPolicyV0::OneShot,
            bootstrap: ioi_types::app::QuvDomainBootstrapV0::HandoffBoundary {
                activation_height: 8,
            },
            domain_id: domain,
            authority_mode: QuvAuthorityModeV0::Owned,
            owner: Some(owner),
            delta_rt_millis: 10,
            qualified_delta_rt_envelope_millis: 8,
            qualified_max_configured_members: 4,
            continuation_millis: 10,
        };
        let vote_preimage = consensus_vote_signing_bytes(7, 0, &[5; 32]).unwrap();
        let mut boundary_signatures =
            vec![(owner, owner_key.sign(&vote_preimage).unwrap().to_bytes())];
        boundary_signatures.extend(other_old_keys.iter().take(2).map(|key| {
            let public = key.public_key().to_bytes();
            let account = AccountId(
                account_id_from_key_material(SignatureSuite::ML_DSA_44, &public).unwrap(),
            );
            (account, key.sign(&vote_preimage).unwrap().to_bytes())
        }));
        let handoff = QuvConfigurationHandoffV0 {
            network_id: network,
            old_configuration_root: old_root,
            successor_set: successor.clone(),
            activation_height: 8,
            old_authority_expiry_height: 7,
            predecessor_candidate_hash: quv_handoff_initial_predecessor(
                network, old_root, 8, 7, [5; 32], &[6; 32],
            )
            .unwrap(),
            state_height: 7,
            state_block_hash: [5; 32],
            state_root: vec![6; 32],
            boundary_qc: QuorumCertificate {
                height: 7,
                view: 0,
                block_hash: [5; 32],
                signatures: boundary_signatures,
                aggregated_signature: vec![],
                signers_bitfield: vec![],
            },
        };
        let mut candidate = QuvCandidateV0 {
            slot: QuvSlotV0 {
                configuration_root: old_root,
                policy_root: provisioned_policy_root(&policy).unwrap(),
                network_id: network,
                domain_id: domain,
                slot: 8,
                predecessor: handoff.predecessor_candidate_hash,
                authority_mode: QuvAuthorityModeV0::Owned,
            },
            payload_hash: quv_handoff_payload_hash(&handoff).unwrap(),
            authorizer: owner,
            authority_signature: Vec::new(),
        };
        candidate.authority_signature = owner_key
            .sign(&quv_candidate_authority_signing_bytes(&candidate).unwrap())
            .unwrap()
            .to_bytes();
        let envelope = QuvConfigurationHandoffEnvelopeV0 { handoff, candidate };
        let mut keys = ioi_consensus::aft::authenticated_quorum::ValidatorKeyRegistry::new();
        keys.learn_raw_public_key(SignatureSuite::ML_DSA_44, &owner_public)
            .unwrap();
        for key in &other_old_keys {
            keys.learn_raw_public_key(SignatureSuite::ML_DSA_44, &key.public_key().to_bytes())
                .unwrap();
        }
        validate_handoff_source(
            &envelope,
            &old,
            &successor,
            &keys,
            std::slice::from_ref(&policy),
            network,
            AftSafetyMode::ClassicBft,
        )
        .expect("exact rooted source validates");

        let mut wrong_bootstrap = policy.clone();
        wrong_bootstrap.bootstrap = ioi_types::app::QuvDomainBootstrapV0::Fixed {
            initial_slot: envelope.handoff.activation_height,
            predecessor: envelope.candidate.slot.predecessor,
        };
        let error = validate_handoff_source(
            &envelope,
            &old,
            &successor,
            &keys,
            std::slice::from_ref(&wrong_bootstrap),
            network,
            AftSafetyMode::ClassicBft,
        )
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("exact rooted boundary bootstrap"));

        let mut forged_qc = envelope.clone();
        forged_qc.handoff.boundary_qc.signatures[0].1[0] ^= 1;
        forged_qc.candidate.payload_hash = quv_handoff_payload_hash(&forged_qc.handoff).unwrap();
        forged_qc.candidate.authority_signature = owner_key
            .sign(&quv_candidate_authority_signing_bytes(&forged_qc.candidate).unwrap())
            .unwrap()
            .to_bytes();
        assert!(validate_handoff_source(
            &forged_qc,
            &old,
            &successor,
            &keys,
            std::slice::from_ref(&policy),
            network,
            AftSafetyMode::ClassicBft,
        )
        .is_err());

        let mut substituted = successor;
        substituted.validators.swap(0, 1);
        assert!(validate_handoff_source(
            &envelope,
            &old,
            &substituted,
            &keys,
            &[],
            network,
            AftSafetyMode::ClassicBft,
        )
        .is_err());
    }
}
