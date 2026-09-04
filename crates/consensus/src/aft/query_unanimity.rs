//! Online Query-Unanimity Verification (`aft_quv_v0`).
//!
//! QUV is not a portable certificate and is not a replacement consensus mode.
//! An executor pushes one rooted candidate to every configured member, waits
//! the complete rooted round-trip interval, and decides from every valid reply
//! delivered in that interval. Correct members durably record a candidate
//! before signing their complete slot snapshot.

use fs2::FileExt;
use ioi_types::app::{AccountId, SignatureSuite, ValidatorSetV1};
pub use ioi_types::app::{
    QuvAcceptedAuditEvidenceV0, QuvAuthorityModeV0, QuvCandidateV0, QuvConfigurationHandoffV0,
    QuvHash, QuvNonce, QuvPushQueryV0, QuvReplyV0, QuvSlotV0, QUV_MAX_CONFIGURED_MEMBERS_V0,
    QUV_PROFILE_V0,
};
use ioi_types::codec;
use parity_scale_codec::{Decode, Encode};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use thiserror::Error;

const STORE_MAGIC_V0: [u8; 8] = *b"AFTQUV00";
const STORE_SCHEMA_V0: u16 = 1;
const STORE_MAX_BYTES: u64 = 512 * 1024 * 1024;
const STORE_MAX_SLOTS: usize = 1_000_000;
const STORE_MAX_CANDIDATES_PER_SLOT: usize = 4_096;
const CANDIDATE_HASH_DOMAIN_V0: &[u8] = b"ioi/aft/quv-candidate/v0";
const POLICY_ROOT_DOMAIN_V0: &[u8] = b"ioi/aft/quv-policy/v0";
const CANDIDATE_AUTHORITY_DOMAIN_V0: &[u8] = b"AFT-QUV-CANDIDATE-v0";
const SNAPSHOT_HASH_DOMAIN_V0: &[u8] = b"ioi/aft/quv-snapshot/v0";
const REPLY_SIGNING_DOMAIN_V0: &[u8] = b"AFT-QUV-REPLY-v0";
const STORE_HEAD_DOMAIN_V0: &[u8] = b"ioi/aft/quv-store-head/v0";
const ANCHOR_TAG_DOMAIN_V0: &[u8] = b"ioi/aft/quv-anchor-tag/v0";
const HANDOFF_DOMAIN_ID_V0: &[u8] = b"ioi/aft/quv-handoff-domain/v0";
const HANDOFF_INITIAL_PREDECESSOR_V0: &[u8] = b"ioi/aft/quv-handoff-initial-predecessor/v0";
const HANDOFF_PAYLOAD_HASH_V0: &[u8] = b"ioi/aft/quv-handoff-payload/v0";
const HANDOFF_STATE_ROOT_MAX_BYTES_V0: usize = 4 * 1024;
const HANDOFF_STORE_MAGIC_V0: [u8; 8] = *b"AFTHOFF0";
const HANDOFF_STORE_SCHEMA_V0: u16 = 1;
const HANDOFF_STORE_HEAD_DOMAIN_V0: &[u8] = b"ioi/aft/quv-handoff-store-head/v0";
const HANDOFF_ANCHOR_TAG_DOMAIN_V0: &[u8] = b"ioi/aft/quv-handoff-anchor-tag/v0";

/// Derive the handoff conflict domain from both configuration roots. The
/// candidate cannot choose a different domain while retaining validity.
pub fn quv_handoff_domain_id(
    network_id: QuvHash,
    old_configuration_root: QuvHash,
    successor_configuration_root: QuvHash,
    activation_height: u64,
) -> Result<QuvHash, QuvError> {
    if network_id == [0; 32]
        || old_configuration_root == [0; 32]
        || successor_configuration_root == [0; 32]
        || activation_height <= 1
    {
        return Err(QuvError::InvalidHandoff);
    }
    hash_canonical(&(
        HANDOFF_DOMAIN_ID_V0.to_vec(),
        network_id,
        old_configuration_root,
        successor_configuration_root,
        activation_height,
    ))
}

/// Derive the rooted initial predecessor for a configuration handoff domain.
///
/// A handoff conflict domain is unique to one old/successor-root transition,
/// so its first QUV slot has no earlier QUV candidate. Its predecessor is
/// therefore this commitment to the exact final old-root state, rather than a
/// value nominated by the candidate source.
pub fn quv_handoff_initial_predecessor(
    network_id: QuvHash,
    old_configuration_root: QuvHash,
    activation_height: u64,
    state_height: u64,
    state_block_hash: QuvHash,
    state_root: &[u8],
) -> Result<QuvHash, QuvError> {
    if network_id == [0; 32]
        || old_configuration_root == [0; 32]
        || activation_height <= 1
        || state_height != activation_height - 1
        || state_block_hash == [0; 32]
        || state_root.is_empty()
        || state_root.len() > HANDOFF_STATE_ROOT_MAX_BYTES_V0
    {
        return Err(QuvError::InvalidHandoff);
    }
    hash_canonical(&(
        HANDOFF_INITIAL_PREDECESSOR_V0.to_vec(),
        network_id,
        old_configuration_root,
        activation_height,
        state_height,
        state_block_hash,
        state_root.to_vec(),
    ))
}

pub fn quv_handoff_payload_hash(handoff: &QuvConfigurationHandoffV0) -> Result<QuvHash, QuvError> {
    validate_quv_handoff_payload(handoff)?;
    hash_canonical(&(HANDOFF_PAYLOAD_HASH_V0.to_vec(), handoff))
}

/// Validate the complete transition payload independently of any candidate.
pub fn validate_quv_handoff_payload(handoff: &QuvConfigurationHandoffV0) -> Result<(), QuvError> {
    let successor_root = ioi_types::app::canonical_validator_set_hash(&handoff.successor_set)
        .map_err(QuvError::Candidate)?;
    let expected_expiry = handoff
        .activation_height
        .checked_sub(1)
        .ok_or(QuvError::InvalidHandoff)?;
    let total_weight = handoff
        .successor_set
        .validators
        .iter()
        .try_fold(0_u128, |sum, member| sum.checked_add(member.weight))
        .ok_or(QuvError::InvalidHandoff)?;
    let expected_predecessor = quv_handoff_initial_predecessor(
        handoff.network_id,
        handoff.old_configuration_root,
        handoff.activation_height,
        handoff.state_height,
        handoff.state_block_hash,
        &handoff.state_root,
    )?;
    if handoff.network_id == [0; 32]
        || handoff.old_configuration_root == [0; 32]
        || successor_root == [0; 32]
        || handoff.activation_height <= 1
        || handoff.old_authority_expiry_height != expected_expiry
        || handoff.state_height != expected_expiry
        || handoff.predecessor_candidate_hash != expected_predecessor
        || handoff.state_block_hash == [0; 32]
        || handoff.state_root.is_empty()
        || handoff.state_root.len() > HANDOFF_STATE_ROOT_MAX_BYTES_V0
        || handoff.boundary_qc.height != handoff.state_height
        || handoff.boundary_qc.block_hash != handoff.state_block_hash
        || handoff.boundary_qc.signatures.is_empty()
        || handoff.successor_set.effective_from_height != handoff.activation_height
        || handoff.successor_set.validators.len() < 2
        || handoff.successor_set.validators.len() > QUV_MAX_CONFIGURED_MEMBERS_V0
        || handoff.successor_set.total_weight != total_weight
        || total_weight == 0
        || handoff
            .successor_set
            .validators
            .windows(2)
            .any(|pair| pair[0].account_id >= pair[1].account_id)
        || handoff.successor_set.validators.iter().any(|member| {
            member.weight == 0
                || member.consensus_key.suite != SignatureSuite::ML_DSA_44
                || member.consensus_key.since_height > handoff.activation_height
        })
    {
        return Err(QuvError::InvalidHandoff);
    }
    Ok(())
}

/// Bind a generic QUV candidate to one exact canonical handoff payload.
pub fn validate_quv_handoff_candidate(
    candidate: &QuvCandidateV0,
    handoff: &QuvConfigurationHandoffV0,
) -> Result<QuvHash, QuvError> {
    validate_quv_handoff_payload(handoff)?;
    let successor_root = ioi_types::app::canonical_validator_set_hash(&handoff.successor_set)
        .map_err(QuvError::Candidate)?;
    let expected_domain = quv_handoff_domain_id(
        handoff.network_id,
        handoff.old_configuration_root,
        successor_root,
        handoff.activation_height,
    )?;
    let payload_hash = quv_handoff_payload_hash(handoff)?;
    if candidate.slot.configuration_root != handoff.old_configuration_root
        || candidate.slot.network_id != handoff.network_id
        || candidate.slot.domain_id != expected_domain
        || candidate.slot.slot != handoff.activation_height
        || candidate.slot.predecessor != handoff.predecessor_candidate_hash
        || candidate.payload_hash != payload_hash
    {
        return Err(QuvError::InvalidHandoff);
    }
    Ok(successor_root)
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
struct QuvUnsignedReplyV0 {
    verifier_nonce: QuvNonce,
    member: AccountId,
    slot: QuvSlotV0,
    candidate_hash: QuvHash,
    snapshot_hash: QuvHash,
    complete_snapshot: Vec<QuvCandidateV0>,
}

pub fn quv_candidate_authority_signing_bytes(
    candidate: &QuvCandidateV0,
) -> Result<Vec<u8>, QuvError> {
    codec::to_bytes_canonical(&(
        CANDIDATE_AUTHORITY_DOMAIN_V0.to_vec(),
        &candidate.slot,
        candidate.payload_hash,
        &candidate.authorizer,
    ))
    .map_err(QuvError::Codec)
}

pub fn quv_candidate_hash(candidate: &QuvCandidateV0) -> Result<QuvHash, QuvError> {
    hash_canonical(&(CANDIDATE_HASH_DOMAIN_V0.to_vec(), candidate))
}

/// Commit the independently provisioned policy, including the complete
/// safety-critical round-trip bound. Candidate bytes cannot select this root.
pub fn quv_policy_root(
    domain_id: QuvHash,
    authority_mode: QuvAuthorityModeV0,
    owner: Option<AccountId>,
    delta_rt_millis: u64,
    continuation_millis: u64,
) -> Result<QuvHash, QuvError> {
    if domain_id == [0; 32]
        || delta_rt_millis == 0
        || continuation_millis == 0
        || matches!(
            (authority_mode, owner),
            (QuvAuthorityModeV0::Owned, None) | (QuvAuthorityModeV0::Unowned, Some(_))
        )
    {
        return Err(QuvError::InvalidRootedContext);
    }
    hash_canonical(&(
        POLICY_ROOT_DOMAIN_V0.to_vec(),
        domain_id,
        authority_mode,
        owner,
        delta_rt_millis,
        continuation_millis,
    ))
}

pub fn quv_reply_signing_bytes(reply: &QuvReplyV0) -> Result<Vec<u8>, QuvError> {
    let unsigned = QuvUnsignedReplyV0 {
        verifier_nonce: reply.verifier_nonce,
        member: reply.member.clone(),
        slot: reply.slot.clone(),
        candidate_hash: reply.candidate_hash,
        snapshot_hash: reply.snapshot_hash,
        complete_snapshot: reply.complete_snapshot.clone(),
    };
    codec::to_bytes_canonical(&(REPLY_SIGNING_DOMAIN_V0.to_vec(), unsigned))
        .map_err(QuvError::Codec)
}

/// Validates rooted candidate syntax, predecessor, and authority signatures.
pub trait QuvCandidateValidatorV0 {
    fn validate_candidate(&self, candidate: &QuvCandidateV0) -> Result<(), QuvError>;
}

/// Signs as the local rooted member. Production profiles must use ML-DSA.
pub trait QuvMemberSignerV0 {
    fn member(&self) -> &AccountId;
    fn sign_reply(&self, signing_bytes: &[u8]) -> Result<Vec<u8>, QuvError>;
}

/// Rebinds a reply signature to one member of the exact rooted configuration.
pub trait QuvReplyVerifierV0 {
    fn verify_reply_signature(
        &self,
        member: &AccountId,
        signing_bytes: &[u8],
        signature: &[u8],
    ) -> Result<(), QuvError>;
}

/// Native PQ validator for candidate authority. Owned mode binds one exact
/// rooted owner; unowned mode admits any member of the rooted configuration.
pub struct RootedQuvCandidateValidatorV0<'a> {
    set: &'a ValidatorSetV1,
    keys: &'a super::authenticated_quorum::ValidatorKeyRegistry,
    activation_height: u64,
    configuration_root: QuvHash,
    policy_root: QuvHash,
    network_id: QuvHash,
    owned_authority: Option<AccountId>,
}

impl<'a> RootedQuvCandidateValidatorV0<'a> {
    pub fn new(
        set: &'a ValidatorSetV1,
        keys: &'a super::authenticated_quorum::ValidatorKeyRegistry,
        activation_height: u64,
        network_id: QuvHash,
        policy_root: QuvHash,
        owned_authority: Option<AccountId>,
    ) -> Result<Self, QuvError> {
        let configuration_root =
            ioi_types::app::canonical_validator_set_hash(set).map_err(QuvError::Candidate)?;
        if network_id == [0; 32] || policy_root == [0; 32] {
            return Err(QuvError::InvalidRootedContext);
        }
        Ok(Self {
            set,
            keys,
            activation_height,
            configuration_root,
            policy_root,
            network_id,
            owned_authority,
        })
    }

    fn verify_member_preimage(
        &self,
        account: &AccountId,
        preimage: &[u8],
        signature: &[u8],
    ) -> Result<(), QuvError> {
        let member = self
            .set
            .validators
            .iter()
            .find(|member| member.account_id == *account)
            .ok_or(QuvError::UnknownMember)?;
        let record = &member.consensus_key;
        if record.suite != SignatureSuite::ML_DSA_44 || self.activation_height < record.since_height
        {
            return Err(QuvError::NonPqOrInactiveKey);
        }
        let key = self
            .keys
            .get(&record.public_key_hash)
            .ok_or(QuvError::UnknownMemberKey)?;
        if key.suite() != SignatureSuite::ML_DSA_44
            || key
                .key_hash()
                .map_err(|error| QuvError::Candidate(error.to_string()))?
                != record.public_key_hash
            || !key.verify(preimage, signature)
        {
            return Err(QuvError::InvalidSignature);
        }
        Ok(())
    }
}

impl QuvCandidateValidatorV0 for RootedQuvCandidateValidatorV0<'_> {
    fn validate_candidate(&self, candidate: &QuvCandidateV0) -> Result<(), QuvError> {
        if candidate.slot.configuration_root != self.configuration_root
            || candidate.slot.policy_root != self.policy_root
            || candidate.slot.network_id != self.network_id
            || candidate.slot.configuration_root == [0; 32]
            || candidate.slot.domain_id == [0; 32]
            || candidate.slot.predecessor == [0; 32]
            || candidate.payload_hash == [0; 32]
            || candidate.slot.slot == 0
        {
            return Err(QuvError::InvalidRootedContext);
        }
        match candidate.slot.authority_mode {
            QuvAuthorityModeV0::Owned
                if self.owned_authority.as_ref() != Some(&candidate.authorizer) =>
            {
                return Err(QuvError::WrongAuthority)
            }
            QuvAuthorityModeV0::Unowned if self.owned_authority.is_some() => {
                return Err(QuvError::WrongAuthority)
            }
            QuvAuthorityModeV0::Owned | QuvAuthorityModeV0::Unowned => {}
        }
        self.verify_member_preimage(
            &candidate.authorizer,
            &quv_candidate_authority_signing_bytes(candidate)?,
            &candidate.authority_signature,
        )
    }
}

/// PQ-only member-reply verifier over the same rooted validator identity map.
pub struct RootedQuvReplyVerifierV0<'a> {
    candidate_validator: &'a RootedQuvCandidateValidatorV0<'a>,
}

impl<'a> RootedQuvReplyVerifierV0<'a> {
    pub fn new(candidate_validator: &'a RootedQuvCandidateValidatorV0<'a>) -> Self {
        Self {
            candidate_validator,
        }
    }
}

impl QuvReplyVerifierV0 for RootedQuvReplyVerifierV0<'_> {
    fn verify_reply_signature(
        &self,
        member: &AccountId,
        signing_bytes: &[u8],
        signature: &[u8],
    ) -> Result<(), QuvError> {
        self.candidate_validator
            .verify_member_preimage(member, signing_bytes, signature)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
struct QuvStoreStateV0 {
    magic: [u8; 8],
    schema: u16,
    generation: u64,
    previous_head: QuvHash,
    slots: BTreeMap<QuvSlotV0, Vec<QuvCandidateV0>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
struct QuvStoreAnchorV0 {
    magic: [u8; 8],
    schema: u16,
    generation: u64,
    head: QuvHash,
    authentication_tag: QuvHash,
}

/// Single-process durable member state. `anchor_path` must be outside clonable
/// member snapshots; otherwise rollback detection is only aspirational.
pub struct DurableQuvMemberV0 {
    path: PathBuf,
    anchor_path: PathBuf,
    _lock: File,
    custody_key: QuvHash,
    state: QuvStoreStateV0,
    head: QuvHash,
}

#[derive(Debug, Clone, Encode, Decode)]
struct InstalledQuvHandoffV0 {
    local_successor: AccountId,
    successor_configuration_root: QuvHash,
    candidate_hash: QuvHash,
    payload_hash: QuvHash,
    handoff: QuvConfigurationHandoffV0,
}

#[derive(Debug, Clone, Encode, Decode)]
struct QuvHandoffStoreStateV0 {
    magic: [u8; 8],
    schema: u16,
    generation: u64,
    previous_head: QuvHash,
    installed: Option<InstalledQuvHandoffV0>,
}

#[derive(Debug, Clone, Encode, Decode)]
struct QuvHandoffStoreAnchorV0 {
    magic: [u8; 8],
    schema: u16,
    generation: u64,
    head: QuvHash,
    authentication_tag: QuvHash,
}

/// Node-local durable gate between a live old-root QUV operation and successor
/// activation. The state file is insufficient by itself: recovery also
/// requires the separately rooted custody-key anchor.
pub struct DurableQuvHandoffV0 {
    path: PathBuf,
    anchor_path: PathBuf,
    _lock: File,
    custody_key: QuvHash,
    state: QuvHandoffStoreStateV0,
    head: QuvHash,
}

impl DurableQuvHandoffV0 {
    pub fn open(
        path: impl AsRef<Path>,
        anchor_path: impl AsRef<Path>,
        custody_key: QuvHash,
    ) -> Result<Self, QuvError> {
        let path = path.as_ref().to_path_buf();
        let anchor_path = anchor_path.as_ref().to_path_buf();
        if path == anchor_path || custody_key == [0; 32] {
            return Err(QuvError::InvalidStoreConfiguration);
        }
        create_parent(&path)?;
        create_parent(&anchor_path)?;
        let lock_path = suffixed(&anchor_path, ".lock");
        let lock = open_private(&lock_path, false)?;
        lock.try_lock_exclusive().map_err(|error| {
            if error.kind() == std::io::ErrorKind::WouldBlock {
                QuvError::StoreBusy
            } else {
                QuvError::Io(error.to_string())
            }
        })?;

        let (state, head) = match (path.exists(), anchor_path.exists()) {
            (false, false) => {
                let state = QuvHandoffStoreStateV0 {
                    magic: HANDOFF_STORE_MAGIC_V0,
                    schema: HANDOFF_STORE_SCHEMA_V0,
                    generation: 0,
                    previous_head: [0; 32],
                    installed: None,
                };
                let head = handoff_store_head(&state)?;
                persist_atomic(
                    &path,
                    &codec::to_bytes_canonical(&state).map_err(QuvError::Codec)?,
                )?;
                persist_handoff_anchor(&anchor_path, &custody_key, 0, head)?;
                (state, head)
            }
            (true, true) => {
                let state: QuvHandoffStoreStateV0 = read_canonical(&path)?;
                validate_handoff_store(&state)?;
                let head = handoff_store_head(&state)?;
                let anchor: QuvHandoffStoreAnchorV0 = read_canonical(&anchor_path)?;
                validate_handoff_anchor(&anchor, &custody_key)?;
                if state.generation == anchor.generation && head == anchor.head {
                    (state, head)
                } else if state.generation == anchor.generation.saturating_add(1)
                    && state.previous_head == anchor.head
                {
                    persist_handoff_anchor(&anchor_path, &custody_key, state.generation, head)?;
                    (state, head)
                } else {
                    return Err(QuvError::RollbackOrFork);
                }
            }
            _ => return Err(QuvError::IncompleteStore),
        };
        Ok(Self {
            path,
            anchor_path,
            _lock: lock,
            custody_key,
            state,
            head,
        })
    }

    /// Consume one fresh process-local authorization and durably install the
    /// exact state that the successor will activate from.
    pub fn install(
        &mut self,
        authorization: QuvOnlineAuthorizationV0,
        handoff: QuvConfigurationHandoffV0,
        local_successor: AccountId,
        observed_state_height: u64,
        observed_state_block_hash: QuvHash,
        observed_state_root: &[u8],
    ) -> Result<QuvHash, QuvError> {
        if Instant::now() > authorization.expires_at {
            return Err(QuvError::ExpiredAuthorization);
        }
        validate_quv_handoff_payload(&handoff)?;
        let successor_root = ioi_types::app::canonical_validator_set_hash(&handoff.successor_set)
            .map_err(QuvError::Candidate)?;
        let expected_domain = quv_handoff_domain_id(
            handoff.network_id,
            handoff.old_configuration_root,
            successor_root,
            handoff.activation_height,
        )?;
        if authorization.slot.configuration_root != handoff.old_configuration_root
            || authorization.slot.network_id != handoff.network_id
            || authorization.slot.domain_id != expected_domain
            || authorization.slot.slot != handoff.activation_height
            || authorization.slot.predecessor != handoff.predecessor_candidate_hash
            || authorization.payload_hash != quv_handoff_payload_hash(&handoff)?
            || observed_state_height != handoff.state_height
            || observed_state_block_hash != handoff.state_block_hash
            || observed_state_root != handoff.state_root
            || !handoff
                .successor_set
                .validators
                .iter()
                .any(|member| member.account_id == local_successor)
        {
            return Err(QuvError::InvalidHandoff);
        }
        let installed = InstalledQuvHandoffV0 {
            local_successor,
            successor_configuration_root: successor_root,
            candidate_hash: authorization.candidate_hash,
            payload_hash: authorization.payload_hash,
            handoff,
        };
        if let Some(existing) = &self.state.installed {
            if codec::to_bytes_canonical(existing).map_err(QuvError::Codec)?
                == codec::to_bytes_canonical(&installed).map_err(QuvError::Codec)?
            {
                return Ok(successor_root);
            }
            return Err(QuvError::ConflictingHandoffInstall);
        }
        let mut next = self.state.clone();
        next.generation = next
            .generation
            .checked_add(1)
            .ok_or(QuvError::GenerationExhausted)?;
        next.previous_head = self.head;
        next.installed = Some(installed);
        let next_head = handoff_store_head(&next)?;
        persist_atomic(
            &self.path,
            &codec::to_bytes_canonical(&next).map_err(QuvError::Codec)?,
        )?;
        persist_handoff_anchor(
            &self.anchor_path,
            &self.custody_key,
            next.generation,
            next_head,
        )?;
        self.state = next;
        self.head = next_head;
        Ok(successor_root)
    }

    /// Recovery-time activation predicate. It recognizes only the exact
    /// locally installed transition; no supplied transcript can create it.
    pub fn permits_activation(
        &self,
        network_id: QuvHash,
        old_configuration_root: QuvHash,
        successor_configuration_root: QuvHash,
        activation_height: u64,
        local_successor: AccountId,
        state_block_hash: QuvHash,
        state_root: &[u8],
    ) -> bool {
        self.state.installed.as_ref().is_some_and(|installed| {
            installed.local_successor == local_successor
                && installed.successor_configuration_root == successor_configuration_root
                && installed.handoff.network_id == network_id
                && installed.handoff.old_configuration_root == old_configuration_root
                && installed.handoff.activation_height == activation_height
                && installed.handoff.state_block_hash == state_block_hash
                && installed.handoff.state_root == state_root
        })
    }

    pub fn generation(&self) -> u64 {
        self.state.generation
    }
}

impl DurableQuvMemberV0 {
    pub fn open(
        path: impl AsRef<Path>,
        anchor_path: impl AsRef<Path>,
        custody_key: QuvHash,
    ) -> Result<Self, QuvError> {
        let path = path.as_ref().to_path_buf();
        let anchor_path = anchor_path.as_ref().to_path_buf();
        if path == anchor_path || custody_key == [0; 32] {
            return Err(QuvError::InvalidStoreConfiguration);
        }
        create_parent(&path)?;
        create_parent(&anchor_path)?;
        let lock_path = suffixed(&anchor_path, ".lock");
        let lock = open_private(&lock_path, false)?;
        lock.try_lock_exclusive().map_err(|error| {
            if error.kind() == std::io::ErrorKind::WouldBlock {
                QuvError::StoreBusy
            } else {
                QuvError::Io(error.to_string())
            }
        })?;

        let (state, head) = match (path.exists(), anchor_path.exists()) {
            (false, false) => {
                let state = QuvStoreStateV0 {
                    magic: STORE_MAGIC_V0,
                    schema: STORE_SCHEMA_V0,
                    generation: 0,
                    previous_head: [0; 32],
                    slots: BTreeMap::new(),
                };
                let head = store_head(&state)?;
                persist_atomic(
                    &path,
                    &codec::to_bytes_canonical(&state).map_err(QuvError::Codec)?,
                )?;
                persist_anchor(&anchor_path, &custody_key, state.generation, head)?;
                (state, head)
            }
            (true, true) => {
                let state: QuvStoreStateV0 = read_canonical(&path)?;
                validate_store(&state)?;
                let head = store_head(&state)?;
                let anchor: QuvStoreAnchorV0 = read_canonical(&anchor_path)?;
                validate_anchor(&anchor, &custody_key)?;
                if state.generation == anchor.generation && head == anchor.head {
                    (state, head)
                } else if state.generation == anchor.generation.saturating_add(1)
                    && state.previous_head == anchor.head
                {
                    // Recovery from a crash after the state rename but before
                    // the independent anchor advanced.
                    persist_anchor(&anchor_path, &custody_key, state.generation, head)?;
                    (state, head)
                } else {
                    return Err(QuvError::RollbackOrFork);
                }
            }
            _ => return Err(QuvError::IncompleteStore),
        };

        Ok(Self {
            path,
            anchor_path,
            _lock: lock,
            custody_key,
            state,
            head,
        })
    }

    /// Validate, linearize, durably commit, then sign. No reply bytes become
    /// observable before both the state and external anchor are durable.
    pub fn process_push<V: QuvCandidateValidatorV0, S: QuvMemberSignerV0>(
        &mut self,
        request: &QuvPushQueryV0,
        validator: &V,
        signer: &S,
    ) -> Result<QuvReplyV0, QuvError> {
        validator.validate_candidate(&request.candidate)?;
        if request.verifier_nonce == [0; 32] {
            return Err(QuvError::InvalidNonce);
        }
        let candidate_hash = quv_candidate_hash(&request.candidate)?;
        let snapshot = self
            .state
            .slots
            .get(&request.candidate.slot)
            .cloned()
            .unwrap_or_default();
        let already_present = snapshot
            .iter()
            .any(|candidate| quv_candidate_hash(candidate).ok() == Some(candidate_hash));
        if !already_present {
            if snapshot.len() >= STORE_MAX_CANDIDATES_PER_SLOT {
                return Err(QuvError::SlotCapacityExceeded);
            }
            if snapshot.is_empty()
                && !self.state.slots.contains_key(&request.candidate.slot)
                && self.state.slots.len() >= STORE_MAX_SLOTS
            {
                return Err(QuvError::StoreCapacityExceeded);
            }
            let mut next = self.state.clone();
            next.generation = next
                .generation
                .checked_add(1)
                .ok_or(QuvError::GenerationExhausted)?;
            next.previous_head = self.head;
            next.slots
                .entry(request.candidate.slot.clone())
                .or_default()
                .push(request.candidate.clone());
            let next_head = store_head(&next)?;
            persist_atomic(
                &self.path,
                &codec::to_bytes_canonical(&next).map_err(QuvError::Codec)?,
            )?;
            persist_anchor(
                &self.anchor_path,
                &self.custody_key,
                next.generation,
                next_head,
            )?;
            self.state = next;
            self.head = next_head;
        }

        let complete_snapshot = self
            .state
            .slots
            .get(&request.candidate.slot)
            .cloned()
            .ok_or(QuvError::CorruptStore)?;
        let snapshot_hash = snapshot_hash(&request.candidate.slot, &complete_snapshot)?;
        let mut reply = QuvReplyV0 {
            verifier_nonce: request.verifier_nonce,
            member: signer.member().clone(),
            slot: request.candidate.slot.clone(),
            candidate_hash,
            snapshot_hash,
            complete_snapshot,
            signature: Vec::new(),
        };
        reply.signature = signer.sign_reply(&quv_reply_signing_bytes(&reply)?)?;
        if reply.signature.is_empty() {
            return Err(QuvError::InvalidSignature);
        }
        Ok(reply)
    }

    pub fn generation(&self) -> u64 {
        self.state.generation
    }
}

/// Process-local, single-use authorization. It intentionally implements
/// neither `Clone` nor any serialization trait.
#[derive(Debug)]
pub struct QuvOnlineAuthorizationV0 {
    candidate_hash: QuvHash,
    payload_hash: QuvHash,
    slot: QuvSlotV0,
    verifier_nonce: QuvNonce,
    expires_at: Instant,
    audit: agentgres::consequence::OnlineEffectAuthorizationAuditV1,
}

impl QuvOnlineAuthorizationV0 {
    pub fn candidate_hash(&self) -> QuvHash {
        self.candidate_hash
    }

    pub fn slot(&self) -> &QuvSlotV0 {
        &self.slot
    }

    pub fn payload_hash(&self) -> QuvHash {
        self.payload_hash
    }

    pub fn verifier_nonce(&self) -> QuvNonce {
        self.verifier_nonce
    }
}

/// One complete online executor operation. Callers must deliver the same
/// request to every configured member and retain every reply until `finish`.
pub struct QuvOnlineOperationV0 {
    request: QuvPushQueryV0,
    configured_members: BTreeSet<AccountId>,
    decision_interval: Duration,
    continuation_interval: Duration,
    started: Instant,
    replies: Vec<QuvReplyV0>,
}

impl QuvOnlineOperationV0 {
    pub fn start(
        request: QuvPushQueryV0,
        configured_members: BTreeSet<AccountId>,
        decision_interval: Duration,
        continuation_interval: Duration,
    ) -> Result<Self, QuvError> {
        if request.verifier_nonce == [0; 32]
            || configured_members.is_empty()
            || decision_interval.is_zero()
            || continuation_interval.is_zero()
        {
            return Err(QuvError::InvalidOperation);
        }
        Ok(Self {
            request,
            configured_members,
            decision_interval,
            continuation_interval,
            started: Instant::now(),
            replies: Vec::new(),
        })
    }

    pub fn request(&self) -> &QuvPushQueryV0 {
        &self.request
    }

    pub fn observe_reply(&mut self, reply: QuvReplyV0) {
        // A correct member emits exactly one reply for an operation. Retain at
        // most the first authenticated member response so a Byzantine member
        // cannot consume unbounded verifier memory or timing-lane capacity.
        if !self
            .replies
            .iter()
            .any(|existing| existing.member == reply.member)
        {
            self.replies.push(reply);
        }
    }

    pub fn remaining(&self) -> Duration {
        self.decision_interval
            .saturating_sub(self.started.elapsed())
    }

    pub fn finish<V: QuvCandidateValidatorV0, R: QuvReplyVerifierV0>(
        self,
        candidate_validator: &V,
        reply_verifier: &R,
    ) -> Result<QuvOnlineAuthorizationV0, QuvError> {
        let elapsed = self.started.elapsed();
        self.finish_at(elapsed, candidate_validator, reply_verifier)
    }

    /// Event-loop entry point. `elapsed` must come from the same monotonic
    /// clock used to start the operation.
    pub fn finish_at<V: QuvCandidateValidatorV0, R: QuvReplyVerifierV0>(
        self,
        elapsed: Duration,
        candidate_validator: &V,
        reply_verifier: &R,
    ) -> Result<QuvOnlineAuthorizationV0, QuvError> {
        if elapsed < self.decision_interval {
            return Err(QuvError::DecisionIntervalIncomplete);
        }
        candidate_validator.validate_candidate(&self.request.candidate)?;
        let wanted = quv_candidate_hash(&self.request.candidate)?;
        let mut valid = Vec::new();
        for reply in self.replies {
            if validate_reply(
                &reply,
                &self.request,
                &self.configured_members,
                candidate_validator,
                reply_verifier,
            )
            .is_ok()
            {
                valid.push(reply);
            }
        }
        if valid.is_empty() {
            return Err(QuvError::NoValidReplies);
        }

        match self.request.candidate.slot.authority_mode {
            QuvAuthorityModeV0::Owned => {
                let mut union = BTreeSet::new();
                for reply in &valid {
                    for candidate in &reply.complete_snapshot {
                        union.insert(quv_candidate_hash(candidate)?);
                    }
                }
                if union != BTreeSet::from([wanted]) {
                    return Err(QuvError::ConflictDisclosed);
                }
            }
            QuvAuthorityModeV0::Unowned => {
                for reply in &valid {
                    let first = quv_candidate_hash(
                        reply
                            .complete_snapshot
                            .first()
                            .ok_or(QuvError::InvalidSnapshot)?,
                    )?;
                    if first != wanted {
                        return Err(QuvError::ConflictDisclosed);
                    }
                }
            }
        }

        let binding = agentgres::consequence::OnlineEffectAuthorizationBindingV1 {
            mode: ioi_types::app::EffectAuthorizationModeV1::OnlineQueryUnanimityV0,
            payload_hash: self.request.candidate.payload_hash,
            configuration_root: self.request.candidate.slot.configuration_root,
            conflict_domain_hash: self.request.candidate.slot.domain_id,
            conflict_slot: self.request.candidate.slot.slot,
            policy_root: self.request.candidate.slot.policy_root,
        };
        let audit_evidence = QuvAcceptedAuditEvidenceV0 {
            request: self.request.clone(),
            configured_members: self.configured_members.iter().copied().collect(),
            valid_replies: valid,
            decision_interval_millis: duration_millis(self.decision_interval)?,
            observed_elapsed_millis: duration_millis(elapsed)?,
        };
        let protocol_evidence =
            codec::to_bytes_canonical(&audit_evidence).map_err(QuvError::Codec)?;
        let protocol_evidence_hash =
            agentgres::consequence::online_authorization_audit_evidence_hash(&protocol_evidence)
                .map_err(|error| QuvError::Audit(error.to_string()))?;
        let audit = agentgres::consequence::OnlineEffectAuthorizationAuditV1 {
            profile: QUV_PROFILE_V0.into(),
            portable_final_receipt: false,
            binding: agentgres::consequence::OnlineEffectAuthorizationAuditBindingV1::from(
                &binding,
            ),
            verifier_nonce: self.request.verifier_nonce,
            protocol_evidence,
            protocol_evidence_hash,
        };
        Ok(QuvOnlineAuthorizationV0 {
            candidate_hash: wanted,
            payload_hash: binding.payload_hash,
            slot: self.request.candidate.slot,
            verifier_nonce: self.request.verifier_nonce,
            expires_at: Instant::now()
                .checked_add(self.continuation_interval)
                .ok_or(QuvError::InvalidOperation)?,
            audit,
        })
    }
}

impl agentgres::consequence::ImmediateOnlineEffectAuthorizationV1 for QuvOnlineAuthorizationV0 {
    fn consume(
        self,
    ) -> Result<
        agentgres::consequence::ConsumedOnlineEffectAuthorizationV1,
        agentgres::consequence::ConsequenceError,
    > {
        if Instant::now() > self.expires_at {
            return Err(agentgres::consequence::ConsequenceError::InvalidOnlineAuthorization);
        }
        Ok(
            agentgres::consequence::ConsumedOnlineEffectAuthorizationV1 {
                audit: self.audit,
                binding: agentgres::consequence::OnlineEffectAuthorizationBindingV1 {
                    mode: ioi_types::app::EffectAuthorizationModeV1::OnlineQueryUnanimityV0,
                    payload_hash: self.payload_hash,
                    configuration_root: self.slot.configuration_root,
                    conflict_domain_hash: self.slot.domain_id,
                    conflict_slot: self.slot.slot,
                    policy_root: self.slot.policy_root,
                },
            },
        )
    }
}

fn duration_millis(duration: Duration) -> Result<u64, QuvError> {
    u64::try_from(duration.as_millis()).map_err(|_| QuvError::InvalidOperation)
}

fn validate_reply<V: QuvCandidateValidatorV0, R: QuvReplyVerifierV0>(
    reply: &QuvReplyV0,
    request: &QuvPushQueryV0,
    configured_members: &BTreeSet<AccountId>,
    candidate_validator: &V,
    reply_verifier: &R,
) -> Result<(), QuvError> {
    let wanted = quv_candidate_hash(&request.candidate)?;
    if reply.verifier_nonce != request.verifier_nonce
        || reply.slot != request.candidate.slot
        || reply.candidate_hash != wanted
        || !configured_members.contains(&reply.member)
        || reply.complete_snapshot.is_empty()
        || reply.complete_snapshot.len() > STORE_MAX_CANDIDATES_PER_SLOT
        || snapshot_hash(&reply.slot, &reply.complete_snapshot)? != reply.snapshot_hash
    {
        return Err(QuvError::InvalidReplyBinding);
    }
    let mut hashes = BTreeSet::new();
    for candidate in &reply.complete_snapshot {
        if candidate.slot != reply.slot || !hashes.insert(quv_candidate_hash(candidate)?) {
            return Err(QuvError::InvalidSnapshot);
        }
        candidate_validator.validate_candidate(candidate)?;
    }
    if !hashes.contains(&wanted) {
        return Err(QuvError::InvalidSnapshot);
    }
    reply_verifier.verify_reply_signature(
        &reply.member,
        &quv_reply_signing_bytes(reply)?,
        &reply.signature,
    )
}

/// Result of replaying the cryptographic/content portion of a QUV audit.
/// `timing_portable` is always false: bytes cannot prove that omitted replies
/// did not arrive or that the executor actually waited the claimed interval.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuvAuditContentAssessmentV0 {
    pub candidate_hash: QuvHash,
    pub valid_reply_count: usize,
    pub timing_portable: bool,
    pub portable_final_receipt: bool,
}

/// Reproduce the byte-checkable portion of an accepted QUV operation. This is
/// an audit function, never an authorization function. It authenticates the
/// included replies and recomputes the decision over those bytes, but cannot
/// establish the live absence/timing fact required for online safety.
pub fn verify_non_authorizing_quv_audit<V: QuvCandidateValidatorV0, R: QuvReplyVerifierV0>(
    audit: &agentgres::consequence::OnlineEffectAuthorizationAuditV1,
    expected_members: BTreeSet<AccountId>,
    expected_decision_interval: Duration,
    candidate_validator: &V,
    reply_verifier: &R,
) -> Result<QuvAuditContentAssessmentV0, QuvError> {
    if audit.profile != QUV_PROFILE_V0
        || audit.portable_final_receipt
        || audit.verifier_nonce == [0; 32]
        || expected_members.is_empty()
        || expected_decision_interval.is_zero()
        || agentgres::consequence::online_authorization_audit_evidence_hash(
            &audit.protocol_evidence,
        )
        .map_err(|error| QuvError::Audit(error.to_string()))?
            != audit.protocol_evidence_hash
    {
        return Err(QuvError::Audit("invalid audit envelope".into()));
    }
    let evidence: QuvAcceptedAuditEvidenceV0 =
        codec::from_bytes_canonical(&audit.protocol_evidence).map_err(QuvError::Codec)?;
    let evidence_members = evidence
        .configured_members
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    if evidence.configured_members.len() != evidence_members.len()
        || evidence_members != expected_members
        || evidence.request.verifier_nonce != audit.verifier_nonce
        || evidence.decision_interval_millis != duration_millis(expected_decision_interval)?
        || evidence.observed_elapsed_millis < evidence.decision_interval_millis
        || evidence.valid_replies.is_empty()
    {
        return Err(QuvError::Audit("invalid audit operation context".into()));
    }
    let request = &evidence.request;
    let binding = &audit.binding;
    if binding.mode != ioi_types::app::EffectAuthorizationModeV1::OnlineQueryUnanimityV0
        || binding.payload_hash != request.candidate.payload_hash
        || binding.configuration_root != request.candidate.slot.configuration_root
        || binding.conflict_domain_hash != request.candidate.slot.domain_id
        || binding.conflict_slot != request.candidate.slot.slot
        || binding.policy_root != request.candidate.slot.policy_root
    {
        return Err(QuvError::Audit("invalid audit effect binding".into()));
    }
    candidate_validator.validate_candidate(&request.candidate)?;
    for reply in &evidence.valid_replies {
        validate_reply(
            reply,
            request,
            &expected_members,
            candidate_validator,
            reply_verifier,
        )?;
    }
    let wanted = quv_candidate_hash(&request.candidate)?;
    match request.candidate.slot.authority_mode {
        QuvAuthorityModeV0::Owned => {
            let mut union = BTreeSet::new();
            for reply in &evidence.valid_replies {
                for candidate in &reply.complete_snapshot {
                    union.insert(quv_candidate_hash(candidate)?);
                }
            }
            if union != BTreeSet::from([wanted]) {
                return Err(QuvError::ConflictDisclosed);
            }
        }
        QuvAuthorityModeV0::Unowned => {
            for reply in &evidence.valid_replies {
                let first = reply
                    .complete_snapshot
                    .first()
                    .ok_or(QuvError::InvalidSnapshot)?;
                if quv_candidate_hash(first)? != wanted {
                    return Err(QuvError::ConflictDisclosed);
                }
            }
        }
    }
    Ok(QuvAuditContentAssessmentV0 {
        candidate_hash: wanted,
        valid_reply_count: evidence.valid_replies.len(),
        timing_portable: false,
        portable_final_receipt: false,
    })
}

fn validate_store(state: &QuvStoreStateV0) -> Result<(), QuvError> {
    if state.magic != STORE_MAGIC_V0
        || state.schema != STORE_SCHEMA_V0
        || state.slots.len() > STORE_MAX_SLOTS
    {
        return Err(QuvError::CorruptStore);
    }
    for (slot, candidates) in &state.slots {
        if candidates.is_empty() || candidates.len() > STORE_MAX_CANDIDATES_PER_SLOT {
            return Err(QuvError::CorruptStore);
        }
        let mut hashes = BTreeSet::new();
        for candidate in candidates {
            if candidate.slot != *slot || !hashes.insert(quv_candidate_hash(candidate)?) {
                return Err(QuvError::CorruptStore);
            }
        }
    }
    Ok(())
}

fn validate_handoff_store(state: &QuvHandoffStoreStateV0) -> Result<(), QuvError> {
    if state.magic != HANDOFF_STORE_MAGIC_V0 || state.schema != HANDOFF_STORE_SCHEMA_V0 {
        return Err(QuvError::CorruptStore);
    }
    if let Some(installed) = &state.installed {
        validate_quv_handoff_payload(&installed.handoff)?;
        let successor_root =
            ioi_types::app::canonical_validator_set_hash(&installed.handoff.successor_set)
                .map_err(QuvError::Candidate)?;
        if installed.local_successor == AccountId([0; 32])
            || installed.successor_configuration_root != successor_root
            || installed.candidate_hash == [0; 32]
            || installed.payload_hash != quv_handoff_payload_hash(&installed.handoff)?
            || !installed
                .handoff
                .successor_set
                .validators
                .iter()
                .any(|member| member.account_id == installed.local_successor)
        {
            return Err(QuvError::CorruptStore);
        }
    }
    Ok(())
}

fn snapshot_hash(slot: &QuvSlotV0, snapshot: &[QuvCandidateV0]) -> Result<QuvHash, QuvError> {
    hash_canonical(&(SNAPSHOT_HASH_DOMAIN_V0.to_vec(), slot, snapshot))
}

fn store_head(state: &QuvStoreStateV0) -> Result<QuvHash, QuvError> {
    hash_canonical(&(STORE_HEAD_DOMAIN_V0.to_vec(), state))
}

fn handoff_store_head(state: &QuvHandoffStoreStateV0) -> Result<QuvHash, QuvError> {
    hash_canonical(&(HANDOFF_STORE_HEAD_DOMAIN_V0.to_vec(), state))
}

fn anchor_tag(key: &QuvHash, generation: u64, head: QuvHash) -> Result<QuvHash, QuvError> {
    hash_canonical(&(
        ANCHOR_TAG_DOMAIN_V0.to_vec(),
        key,
        STORE_MAGIC_V0,
        STORE_SCHEMA_V0,
        generation,
        head,
    ))
}

fn persist_anchor(
    path: &Path,
    key: &QuvHash,
    generation: u64,
    head: QuvHash,
) -> Result<(), QuvError> {
    let anchor = QuvStoreAnchorV0 {
        magic: STORE_MAGIC_V0,
        schema: STORE_SCHEMA_V0,
        generation,
        head,
        authentication_tag: anchor_tag(key, generation, head)?,
    };
    persist_atomic(
        path,
        &codec::to_bytes_canonical(&anchor).map_err(QuvError::Codec)?,
    )
}

fn validate_anchor(anchor: &QuvStoreAnchorV0, key: &QuvHash) -> Result<(), QuvError> {
    if anchor.magic != STORE_MAGIC_V0
        || anchor.schema != STORE_SCHEMA_V0
        || anchor.head == [0; 32]
        || anchor.authentication_tag != anchor_tag(key, anchor.generation, anchor.head)?
    {
        return Err(QuvError::InvalidAnchor);
    }
    Ok(())
}

fn handoff_anchor_tag(key: &QuvHash, generation: u64, head: QuvHash) -> Result<QuvHash, QuvError> {
    hash_canonical(&(
        HANDOFF_ANCHOR_TAG_DOMAIN_V0.to_vec(),
        key,
        HANDOFF_STORE_MAGIC_V0,
        HANDOFF_STORE_SCHEMA_V0,
        generation,
        head,
    ))
}

fn persist_handoff_anchor(
    path: &Path,
    key: &QuvHash,
    generation: u64,
    head: QuvHash,
) -> Result<(), QuvError> {
    let anchor = QuvHandoffStoreAnchorV0 {
        magic: HANDOFF_STORE_MAGIC_V0,
        schema: HANDOFF_STORE_SCHEMA_V0,
        generation,
        head,
        authentication_tag: handoff_anchor_tag(key, generation, head)?,
    };
    persist_atomic(
        path,
        &codec::to_bytes_canonical(&anchor).map_err(QuvError::Codec)?,
    )
}

fn validate_handoff_anchor(
    anchor: &QuvHandoffStoreAnchorV0,
    key: &QuvHash,
) -> Result<(), QuvError> {
    if anchor.magic != HANDOFF_STORE_MAGIC_V0
        || anchor.schema != HANDOFF_STORE_SCHEMA_V0
        || anchor.head == [0; 32]
        || anchor.authentication_tag != handoff_anchor_tag(key, anchor.generation, anchor.head)?
    {
        return Err(QuvError::InvalidAnchor);
    }
    Ok(())
}

fn hash_canonical<T: Encode>(value: &T) -> Result<QuvHash, QuvError> {
    let bytes = codec::to_bytes_canonical(value).map_err(QuvError::Codec)?;
    ioi_crypto::algorithms::hash::sha256(bytes).map_err(|error| QuvError::Hash(error.to_string()))
}

fn read_canonical<T: Decode>(path: &Path) -> Result<T, QuvError> {
    let metadata = std::fs::metadata(path).map_err(|error| QuvError::Io(error.to_string()))?;
    if metadata.len() > STORE_MAX_BYTES {
        return Err(QuvError::StoreCapacityExceeded);
    }
    let bytes = std::fs::read(path).map_err(|error| QuvError::Io(error.to_string()))?;
    codec::from_bytes_canonical(&bytes).map_err(QuvError::Codec)
}

fn create_parent(path: &Path) -> Result<(), QuvError> {
    let parent = path.parent().ok_or(QuvError::InvalidStoreConfiguration)?;
    std::fs::create_dir_all(parent).map_err(|error| QuvError::Io(error.to_string()))
}

fn suffixed(path: &Path, suffix: &str) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(suffix);
    PathBuf::from(value)
}

fn open_private(path: &Path, truncate: bool) -> Result<File, QuvError> {
    let mut options = OpenOptions::new();
    options
        .create(true)
        .read(true)
        .write(true)
        .truncate(truncate);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
        .open(path)
        .map_err(|error| QuvError::Io(error.to_string()))
}

fn persist_atomic(path: &Path, bytes: &[u8]) -> Result<(), QuvError> {
    let staged = suffixed(path, ".tmp");
    let mut file = open_private(&staged, true)?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|error| QuvError::Io(error.to_string()))?;
    std::fs::rename(&staged, path).map_err(|error| QuvError::Io(error.to_string()))?;
    if let Some(parent) = path.parent() {
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| QuvError::Io(error.to_string()))?;
    }
    Ok(())
}

#[derive(Debug, Error)]
pub enum QuvError {
    #[error("invalid QUV store configuration")]
    InvalidStoreConfiguration,
    #[error("QUV store is already locked")]
    StoreBusy,
    #[error("QUV store and rollback anchor are incomplete")]
    IncompleteStore,
    #[error("QUV store rollback or fork detected")]
    RollbackOrFork,
    #[error("invalid QUV rollback anchor")]
    InvalidAnchor,
    #[error("corrupt QUV member store")]
    CorruptStore,
    #[error("QUV store slot capacity exceeded")]
    StoreCapacityExceeded,
    #[error("QUV candidate capacity exceeded for slot")]
    SlotCapacityExceeded,
    #[error("QUV generation exhausted")]
    GenerationExhausted,
    #[error("invalid QUV nonce")]
    InvalidNonce,
    #[error("invalid QUV operation")]
    InvalidOperation,
    #[error("QUV decision interval is incomplete")]
    DecisionIntervalIncomplete,
    #[error("no valid QUV member reply arrived")]
    NoValidReplies,
    #[error("a valid conflict was disclosed")]
    ConflictDisclosed,
    #[error("invalid QUV reply binding")]
    InvalidReplyBinding,
    #[error("invalid QUV complete snapshot")]
    InvalidSnapshot,
    #[error("invalid QUV member signature")]
    InvalidSignature,
    #[error("QUV member signing failed: {0}")]
    Signing(String),
    #[error("QUV identity is not a rooted configured member")]
    UnknownMember,
    #[error("QUV rooted member key is unavailable")]
    UnknownMemberKey,
    #[error("QUV requires an active ML-DSA-44 key")]
    NonPqOrInactiveKey,
    #[error("QUV candidate authority does not match the rooted policy")]
    WrongAuthority,
    #[error("QUV candidate is outside the exact rooted context")]
    InvalidRootedContext,
    #[error("invalid QUV live configuration handoff")]
    InvalidHandoff,
    #[error("QUV process-local authorization expired before durable handoff install")]
    ExpiredAuthorization,
    #[error("QUV handoff store already contains a different transition")]
    ConflictingHandoffInstall,
    #[error("QUV candidate validation failed: {0}")]
    Candidate(String),
    #[error("QUV codec failure: {0}")]
    Codec(String),
    #[error("QUV hash failure: {0}")]
    Hash(String),
    #[error("QUV audit construction failed: {0}")]
    Audit(String),
    #[error("QUV durable I/O failure: {0}")]
    Io(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentgres::consequence::ImmediateOnlineEffectAuthorizationV1;
    use ioi_api::crypto::{SerializableKey, SigningKeyPair};
    use ioi_crypto::{security::SecurityLevel, sign::dilithium::MldsaScheme};
    use ioi_types::app::{
        account_id_from_key_material, ActiveKeyRecord, QuorumCertificate, ValidatorV1,
    };
    use tempfile::TempDir;

    struct AcceptCandidates;
    impl QuvCandidateValidatorV0 for AcceptCandidates {
        fn validate_candidate(&self, candidate: &QuvCandidateV0) -> Result<(), QuvError> {
            if candidate.authority_signature.is_empty() {
                Err(QuvError::Candidate("missing authority signature".into()))
            } else {
                Ok(())
            }
        }
    }

    struct TestMember(AccountId);
    impl QuvMemberSignerV0 for TestMember {
        fn member(&self) -> &AccountId {
            &self.0
        }

        fn sign_reply(&self, signing_bytes: &[u8]) -> Result<Vec<u8>, QuvError> {
            let mut material = self.0.as_ref().to_vec();
            material.extend_from_slice(signing_bytes);
            Ok(ioi_crypto::algorithms::hash::sha256(material)
                .unwrap()
                .to_vec())
        }
    }

    impl QuvReplyVerifierV0 for TestMember {
        fn verify_reply_signature(
            &self,
            member: &AccountId,
            signing_bytes: &[u8],
            signature: &[u8],
        ) -> Result<(), QuvError> {
            let expected = TestMember(member.clone()).sign_reply(signing_bytes)?;
            if expected == signature {
                Ok(())
            } else {
                Err(QuvError::InvalidSignature)
            }
        }
    }

    fn account(byte: u8) -> AccountId {
        AccountId([byte; 32])
    }

    fn slot(mode: QuvAuthorityModeV0) -> QuvSlotV0 {
        QuvSlotV0 {
            configuration_root: [1; 32],
            policy_root: [6; 32],
            network_id: [2; 32],
            domain_id: [3; 32],
            slot: 7,
            predecessor: [4; 32],
            authority_mode: mode,
        }
    }

    fn candidate(mode: QuvAuthorityModeV0, payload: u8) -> QuvCandidateV0 {
        QuvCandidateV0 {
            slot: slot(mode),
            payload_hash: [payload; 32],
            authorizer: account(9),
            authority_signature: vec![payload],
        }
    }

    fn open_member(temp: &TempDir) -> DurableQuvMemberV0 {
        DurableQuvMemberV0::open(
            temp.path().join("state/quv.scale"),
            temp.path().join("anchor/quv.anchor"),
            [8; 32],
        )
        .unwrap()
    }

    #[test]
    fn writes_before_reply_and_recovers_monotone_snapshot() {
        let temp = TempDir::new().unwrap();
        let signer = TestMember(account(1));
        let x = candidate(QuvAuthorityModeV0::Owned, 10);
        let y = candidate(QuvAuthorityModeV0::Owned, 11);
        let reply_x = open_member(&temp)
            .process_push(
                &QuvPushQueryV0 {
                    verifier_nonce: [5; 32],
                    candidate: x.clone(),
                },
                &AcceptCandidates,
                &signer,
            )
            .unwrap();
        assert_eq!(reply_x.complete_snapshot, vec![x.clone()]);

        let mut restarted = open_member(&temp);
        let reply_y = restarted
            .process_push(
                &QuvPushQueryV0 {
                    verifier_nonce: [6; 32],
                    candidate: y.clone(),
                },
                &AcceptCandidates,
                &signer,
            )
            .unwrap();
        assert_eq!(reply_y.complete_snapshot, vec![x, y]);
        assert_eq!(restarted.generation(), 2);
    }

    #[test]
    fn owned_mode_rejects_a_disclosed_conflict() {
        let temp = TempDir::new().unwrap();
        let signer = TestMember(account(1));
        let mut member = open_member(&temp);
        let x = candidate(QuvAuthorityModeV0::Owned, 10);
        let y = candidate(QuvAuthorityModeV0::Owned, 11);
        member
            .process_push(
                &QuvPushQueryV0 {
                    verifier_nonce: [1; 32],
                    candidate: x,
                },
                &AcceptCandidates,
                &signer,
            )
            .unwrap();
        let request = QuvPushQueryV0 {
            verifier_nonce: [2; 32],
            candidate: y,
        };
        let reply = member
            .process_push(&request, &AcceptCandidates, &signer)
            .unwrap();
        let mut operation = QuvOnlineOperationV0::start(
            request,
            BTreeSet::from([account(1), account(2)]),
            Duration::from_secs(1),
            Duration::from_secs(1),
        )
        .unwrap();
        operation.observe_reply(reply);
        assert!(matches!(
            operation.finish_at(Duration::from_secs(1), &AcceptCandidates, &signer),
            Err(QuvError::ConflictDisclosed)
        ));
    }

    #[test]
    fn silent_byzantine_member_does_not_block_single_candidate() {
        let temp = TempDir::new().unwrap();
        let signer = TestMember(account(1));
        let request = QuvPushQueryV0 {
            verifier_nonce: [3; 32],
            candidate: candidate(QuvAuthorityModeV0::Owned, 10),
        };
        let reply = open_member(&temp)
            .process_push(&request, &AcceptCandidates, &signer)
            .unwrap();
        let mut operation = QuvOnlineOperationV0::start(
            request.clone(),
            BTreeSet::from([account(1), account(2)]),
            Duration::from_secs(1),
            Duration::from_secs(1),
        )
        .unwrap();
        operation.observe_reply(reply);
        assert!(matches!(
            operation.finish_at(Duration::from_millis(999), &AcceptCandidates, &signer),
            Err(QuvError::DecisionIntervalIncomplete)
        ));

        let mut operation = QuvOnlineOperationV0::start(
            request,
            BTreeSet::from([account(1), account(2)]),
            Duration::from_secs(1),
            Duration::from_secs(1),
        )
        .unwrap();
        let reply = open_member(&temp)
            .process_push(operation.request(), &AcceptCandidates, &signer)
            .unwrap();
        operation.observe_reply(reply);
        let authorization = operation
            .finish_at(Duration::from_secs(1), &AcceptCandidates, &signer)
            .unwrap();
        assert_eq!(authorization.slot().slot, 7);
        let consumed = authorization.consume().unwrap();
        let binding = consumed.binding;
        assert_eq!(binding.payload_hash, [10; 32]);
        assert_eq!(binding.configuration_root, [1; 32]);
        assert_eq!(binding.conflict_domain_hash, [3; 32]);
        assert_eq!(binding.conflict_slot, 7);
        assert_eq!(binding.policy_root, [6; 32]);
        assert!(!consumed.audit.portable_final_receipt);
        let assessment = verify_non_authorizing_quv_audit(
            &consumed.audit,
            BTreeSet::from([account(1), account(2)]),
            Duration::from_secs(1),
            &AcceptCandidates,
            &signer,
        )
        .unwrap();
        assert_eq!(assessment.valid_reply_count, 1);
        assert!(!assessment.timing_portable);
        assert!(!assessment.portable_final_receipt);
        let evidence: QuvAcceptedAuditEvidenceV0 =
            codec::from_bytes_canonical(&consumed.audit.protocol_evidence).unwrap();
        assert_eq!(
            assessment.candidate_hash,
            quv_candidate_hash(&evidence.request.candidate).unwrap()
        );
        assert_eq!(
            consumed.audit.protocol_evidence_hash,
            agentgres::consequence::online_authorization_audit_evidence_hash(
                &consumed.audit.protocol_evidence
            )
            .unwrap()
        );
        assert_eq!(evidence.valid_replies.len(), 1);
        assert_eq!(evidence.decision_interval_millis, 1_000);
        assert_eq!(evidence.observed_elapsed_millis, 1_000);

        let mut laundered = consumed.audit;
        laundered.portable_final_receipt = true;
        assert!(verify_non_authorizing_quv_audit(
            &laundered,
            BTreeSet::from([account(1), account(2)]),
            Duration::from_secs(1),
            &AcceptCandidates,
            &signer,
        )
        .is_err());
    }

    #[test]
    fn expired_process_local_authorization_cannot_cross_the_effect_boundary() {
        let evidence = b"expired test authorization".to_vec();
        let authorization = QuvOnlineAuthorizationV0 {
            candidate_hash: [1; 32],
            payload_hash: [2; 32],
            slot: slot(QuvAuthorityModeV0::Owned),
            verifier_nonce: [3; 32],
            expires_at: Instant::now() - Duration::from_millis(1),
            audit: agentgres::consequence::OnlineEffectAuthorizationAuditV1 {
                profile: QUV_PROFILE_V0.into(),
                portable_final_receipt: false,
                binding: agentgres::consequence::OnlineEffectAuthorizationAuditBindingV1 {
                    mode: ioi_types::app::EffectAuthorizationModeV1::OnlineQueryUnanimityV0,
                    payload_hash: [2; 32],
                    configuration_root: [1; 32],
                    conflict_domain_hash: [3; 32],
                    conflict_slot: 7,
                    policy_root: [6; 32],
                },
                verifier_nonce: [3; 32],
                protocol_evidence_hash:
                    agentgres::consequence::online_authorization_audit_evidence_hash(&evidence)
                        .unwrap(),
                protocol_evidence: evidence,
            },
        };
        assert!(authorization.consume().is_err());
    }

    #[test]
    fn exact_context_binding_rejects_cross_slot_reply() {
        let temp = TempDir::new().unwrap();
        let signer = TestMember(account(1));
        let request = QuvPushQueryV0 {
            verifier_nonce: [3; 32],
            candidate: candidate(QuvAuthorityModeV0::Owned, 10),
        };
        let mut reply = open_member(&temp)
            .process_push(&request, &AcceptCandidates, &signer)
            .unwrap();
        reply.slot.slot += 1;
        let mut operation = QuvOnlineOperationV0::start(
            request,
            BTreeSet::from([account(1)]),
            Duration::from_secs(1),
            Duration::from_secs(1),
        )
        .unwrap();
        operation.observe_reply(reply);
        assert!(matches!(
            operation.finish_at(Duration::from_secs(1), &AcceptCandidates, &signer),
            Err(QuvError::NoValidReplies)
        ));
    }

    #[test]
    fn external_anchor_detects_state_rollback() {
        let temp = TempDir::new().unwrap();
        let state_path = temp.path().join("state/quv.scale");
        let anchor_path = temp.path().join("anchor/quv.anchor");
        let signer = TestMember(account(1));
        let mut member = DurableQuvMemberV0::open(&state_path, &anchor_path, [8; 32]).unwrap();
        let old_state = std::fs::read(&state_path).unwrap();
        member
            .process_push(
                &QuvPushQueryV0 {
                    verifier_nonce: [5; 32],
                    candidate: candidate(QuvAuthorityModeV0::Owned, 10),
                },
                &AcceptCandidates,
                &signer,
            )
            .unwrap();
        drop(member);
        std::fs::write(&state_path, old_state).unwrap();
        assert!(matches!(
            DurableQuvMemberV0::open(&state_path, &anchor_path, [8; 32]),
            Err(QuvError::RollbackOrFork)
        ));
    }

    #[test]
    fn live_handoff_candidate_binds_both_roots_and_complete_activation_state() {
        let successor_set = ValidatorSetV1 {
            effective_from_height: 11,
            total_weight: 2,
            validators: vec![20_u8, 21_u8]
                .into_iter()
                .map(|byte| ValidatorV1 {
                    account_id: account(byte),
                    weight: 1,
                    consensus_key: ActiveKeyRecord {
                        suite: SignatureSuite::ML_DSA_44,
                        public_key_hash: [byte; 32],
                        since_height: 1,
                    },
                })
                .collect(),
        };
        let handoff = QuvConfigurationHandoffV0 {
            network_id: [2; 32],
            old_configuration_root: [1; 32],
            successor_set,
            activation_height: 11,
            old_authority_expiry_height: 10,
            predecessor_candidate_hash: quv_handoff_initial_predecessor(
                [2; 32], [1; 32], 11, 10, [5; 32], &[6; 32],
            )
            .unwrap(),
            state_height: 10,
            state_block_hash: [5; 32],
            state_root: vec![6; 32],
            boundary_qc: QuorumCertificate {
                height: 10,
                view: 0,
                block_hash: [5; 32],
                signatures: vec![(account(1), vec![1])],
                aggregated_signature: vec![],
                signers_bitfield: vec![],
            },
        };
        let successor_root =
            ioi_types::app::canonical_validator_set_hash(&handoff.successor_set).unwrap();
        let domain = quv_handoff_domain_id(
            handoff.network_id,
            handoff.old_configuration_root,
            successor_root,
            handoff.activation_height,
        )
        .unwrap();
        let candidate = QuvCandidateV0 {
            slot: QuvSlotV0 {
                configuration_root: handoff.old_configuration_root,
                policy_root: [7; 32],
                network_id: handoff.network_id,
                domain_id: domain,
                slot: handoff.activation_height,
                predecessor: handoff.predecessor_candidate_hash,
                authority_mode: QuvAuthorityModeV0::Owned,
            },
            payload_hash: quv_handoff_payload_hash(&handoff).unwrap(),
            authorizer: account(9),
            authority_signature: vec![8],
        };
        assert_eq!(
            validate_quv_handoff_candidate(&candidate, &handoff).unwrap(),
            successor_root
        );

        let mut substituted = handoff.clone();
        substituted.state_root[0] ^= 1;
        assert!(matches!(
            validate_quv_handoff_candidate(&candidate, &substituted),
            Err(QuvError::InvalidHandoff)
        ));
        let mut source_nominated_predecessor = handoff.clone();
        source_nominated_predecessor.predecessor_candidate_hash = [4; 32];
        assert!(matches!(
            validate_quv_handoff_payload(&source_nominated_predecessor),
            Err(QuvError::InvalidHandoff)
        ));
        let mut substituted_boundary_qc = handoff.clone();
        substituted_boundary_qc.boundary_qc.block_hash = [3; 32];
        assert!(matches!(
            validate_quv_handoff_payload(&substituted_boundary_qc),
            Err(QuvError::InvalidHandoff)
        ));
        let mut premature = handoff;
        premature.state_height = 9;
        assert!(matches!(
            validate_quv_handoff_payload(&premature),
            Err(QuvError::InvalidHandoff)
        ));
    }

    #[test]
    fn live_authorization_is_consumed_into_rollback_anchored_successor_activation() {
        let successor_set = ValidatorSetV1 {
            effective_from_height: 11,
            total_weight: 2,
            validators: vec![20_u8, 21_u8]
                .into_iter()
                .map(|byte| ValidatorV1 {
                    account_id: account(byte),
                    weight: 1,
                    consensus_key: ActiveKeyRecord {
                        suite: SignatureSuite::ML_DSA_44,
                        public_key_hash: [byte; 32],
                        since_height: 1,
                    },
                })
                .collect(),
        };
        let handoff = QuvConfigurationHandoffV0 {
            network_id: [2; 32],
            old_configuration_root: [1; 32],
            successor_set,
            activation_height: 11,
            old_authority_expiry_height: 10,
            predecessor_candidate_hash: quv_handoff_initial_predecessor(
                [2; 32], [1; 32], 11, 10, [5; 32], &[6; 32],
            )
            .unwrap(),
            state_height: 10,
            state_block_hash: [5; 32],
            state_root: vec![6; 32],
            boundary_qc: QuorumCertificate {
                height: 10,
                view: 0,
                block_hash: [5; 32],
                signatures: vec![(account(1), vec![1])],
                aggregated_signature: vec![],
                signers_bitfield: vec![],
            },
        };
        let successor_root =
            ioi_types::app::canonical_validator_set_hash(&handoff.successor_set).unwrap();
        let request = QuvPushQueryV0 {
            verifier_nonce: [3; 32],
            candidate: QuvCandidateV0 {
                slot: QuvSlotV0 {
                    configuration_root: handoff.old_configuration_root,
                    policy_root: [7; 32],
                    network_id: handoff.network_id,
                    domain_id: quv_handoff_domain_id(
                        handoff.network_id,
                        handoff.old_configuration_root,
                        successor_root,
                        handoff.activation_height,
                    )
                    .unwrap(),
                    slot: handoff.activation_height,
                    predecessor: handoff.predecessor_candidate_hash,
                    authority_mode: QuvAuthorityModeV0::Owned,
                },
                payload_hash: quv_handoff_payload_hash(&handoff).unwrap(),
                authorizer: account(9),
                authority_signature: vec![8],
            },
        };
        let temp = TempDir::new().unwrap();
        let signer = TestMember(account(1));
        let reply = open_member(&temp)
            .process_push(&request, &AcceptCandidates, &signer)
            .unwrap();
        let mut operation = QuvOnlineOperationV0::start(
            request,
            BTreeSet::from([account(1)]),
            Duration::from_secs(1),
            Duration::from_secs(1),
        )
        .unwrap();
        operation.observe_reply(reply);
        let authorization = operation
            .finish_at(Duration::from_secs(1), &AcceptCandidates, &signer)
            .unwrap();

        let state_path = temp.path().join("handoff/state.scale");
        let anchor_path = temp.path().join("handoff-anchor/state.anchor");
        let mut store = DurableQuvHandoffV0::open(&state_path, &anchor_path, [9; 32]).unwrap();
        let pre_install_state = std::fs::read(&state_path).unwrap();
        assert_eq!(
            store
                .install(
                    authorization,
                    handoff.clone(),
                    account(20),
                    10,
                    [5; 32],
                    &[6; 32],
                )
                .unwrap(),
            successor_root
        );
        assert_eq!(store.generation(), 1);
        assert!(store.permits_activation(
            [2; 32],
            [1; 32],
            successor_root,
            11,
            account(20),
            [5; 32],
            &[6; 32],
        ));
        drop(store);
        let recovered = DurableQuvHandoffV0::open(&state_path, &anchor_path, [9; 32]).unwrap();
        assert!(recovered.permits_activation(
            [2; 32],
            [1; 32],
            successor_root,
            11,
            account(20),
            [5; 32],
            &[6; 32],
        ));
        assert!(!recovered.permits_activation(
            [2; 32],
            [1; 32],
            successor_root,
            12,
            account(20),
            [5; 32],
            &[6; 32],
        ));
        drop(recovered);
        std::fs::write(&state_path, pre_install_state).unwrap();
        assert!(matches!(
            DurableQuvHandoffV0::open(&state_path, &anchor_path, [9; 32]),
            Err(QuvError::RollbackOrFork)
        ));
    }

    #[test]
    fn rooted_owned_policy_is_not_nominated_by_the_candidate() {
        let owner_key = MldsaScheme::new(SecurityLevel::Level2)
            .generate_keypair()
            .unwrap();
        let owner_public = owner_key.public_key().to_bytes();
        let owner_hash =
            account_id_from_key_material(SignatureSuite::ML_DSA_44, &owner_public).unwrap();
        let owner = AccountId(owner_hash);
        let set = ValidatorSetV1 {
            effective_from_height: 1,
            total_weight: 1,
            validators: vec![ValidatorV1 {
                account_id: owner,
                weight: 1,
                consensus_key: ActiveKeyRecord {
                    suite: SignatureSuite::ML_DSA_44,
                    public_key_hash: owner_hash,
                    since_height: 1,
                },
            }],
        };
        let mut keys = super::super::authenticated_quorum::ValidatorKeyRegistry::new();
        keys.learn_raw_public_key(SignatureSuite::ML_DSA_44, &owner_public)
            .unwrap();
        let validator =
            RootedQuvCandidateValidatorV0::new(&set, &keys, 1, [2; 32], [6; 32], Some(owner))
                .unwrap();
        let mut candidate = QuvCandidateV0 {
            slot: QuvSlotV0 {
                configuration_root: ioi_types::app::canonical_validator_set_hash(&set).unwrap(),
                policy_root: [6; 32],
                network_id: [2; 32],
                domain_id: [3; 32],
                slot: 1,
                predecessor: [4; 32],
                authority_mode: QuvAuthorityModeV0::Owned,
            },
            payload_hash: [5; 32],
            authorizer: owner,
            authority_signature: Vec::new(),
        };
        candidate.authority_signature = owner_key
            .sign(&quv_candidate_authority_signing_bytes(&candidate).unwrap())
            .unwrap()
            .to_bytes();
        validator.validate_candidate(&candidate).unwrap();

        candidate.authorizer = account(99);
        assert!(matches!(
            validator.validate_candidate(&candidate),
            Err(QuvError::WrongAuthority)
        ));
    }

    #[test]
    fn policy_root_binds_authority_and_complete_timing_bounds() {
        let baseline = quv_policy_root(
            [3; 32],
            QuvAuthorityModeV0::Owned,
            Some(account(9)),
            1_000,
            50,
        )
        .unwrap();
        assert_ne!(
            baseline,
            quv_policy_root(
                [3; 32],
                QuvAuthorityModeV0::Owned,
                Some(account(8)),
                1_000,
                50,
            )
            .unwrap()
        );
        assert_ne!(
            baseline,
            quv_policy_root(
                [3; 32],
                QuvAuthorityModeV0::Owned,
                Some(account(9)),
                999,
                50,
            )
            .unwrap()
        );
        assert_ne!(
            baseline,
            quv_policy_root(
                [3; 32],
                QuvAuthorityModeV0::Owned,
                Some(account(9)),
                1_000,
                49,
            )
            .unwrap()
        );
    }
}
