//! Production session-state boundary for pairwise `aft-pq-channel-v1` links.
//!
//! The swarm integration owns one manager. Reconfiguration or disconnect drops
//! all traffic keys and pending ephemeral KEM state; v1 has no session
//! resumption, so a restart always performs a fresh handshake.

use anyhow::{anyhow, Result};
use ioi_crypto::sign::dilithium::MldsaKeyPair;
use ioi_crypto::transport::pq_authenticated_channel::{
    accept_pq_channel, complete_pq_channel, finish_pq_channel, start_pq_channel,
    PqChannelClientFinishV1, PqChannelClientHelloV1, PqChannelContentTypeV1, PqChannelDirectionV1,
    PqChannelInitiatorState, PqChannelRecordOpener, PqChannelRecordSealer, PqChannelRecordV1,
    PqChannelResponderState, PqChannelScopeV1, PqChannelServerHelloV1,
    PQ_CHANNEL_MAX_RECORD_PLAINTEXT_V1,
};
use ioi_types::app::{AccountId, AftAsyncCarrierV1, QuvNonce, QuvPushQueryV0};
use ioi_types::codec;
use libp2p::PeerId;
use parity_scale_codec::{Decode, Encode};
use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::sync::PqConsensusPayloadV1;

mod outbox_arena;
mod outbox_decode;
mod outbox_index;
mod outbox_reservation;

const PQ_OUTBOX_PROTOCOL_VERSION: u16 = 1;
const PQ_OUTBOX_SCHEMA_VERSION: u16 = 2;
const PQ_OUTBOX_MESSAGE_ID_DOMAIN: &[u8] = b"ioi/aft/pq-outbox-message/v2";
const PQ_OUTBOX_NORMAL_PER_RECIPIENT_MAX: usize =
    ioi_types::app::QUV_OUTBOX_NORMAL_RECORDS_PER_RECIPIENT_V0;
const PQ_OUTBOX_QUV_RESERVED_PER_RECIPIENT: usize =
    ioi_types::app::QUV_OUTBOX_RESERVED_RECORDS_PER_RECIPIENT_V0;
const PQ_OUTBOX_PER_RECIPIENT_MAX: usize =
    PQ_OUTBOX_NORMAL_PER_RECIPIENT_MAX + PQ_OUTBOX_QUV_RESERVED_PER_RECIPIENT;
const PQ_PROVISIONAL_ENROLLMENTS_MAX: usize = 4_096;
const PQ_PROVISIONAL_PER_ACCOUNT_MAX: usize = 4;
const PQ_PROVISIONAL_ENROLLMENT_LIFETIME: Duration = Duration::from_secs(30);

#[derive(Default)]
struct OutboxByteUsage {
    usage: HashMap<AccountId, (u64, u64, bool, bool)>,
}
impl OutboxByteUsage {
    fn observe(&mut self, recipient: AccountId, payload: &PqConsensusPayloadV1) -> Result<()> {
        let size = payload.encoded_size() as u64;
        let (normal, quv, push_seen, reply_seen) = self.usage.entry(recipient).or_default();
        let lane = match payload {
            PqConsensusPayloadV1::QuvPushQuery(_) => Some(push_seen),
            PqConsensusPayloadV1::QuvReply(_) => Some(reply_seen),
            _ => None,
        };
        if let Some(seen) = lane {
            if *seen {
                return Err(anyhow!("QUV outbox lane already occupied"));
            }
            *seen = true;
        }
        let (used, limit) = if is_quv_payload(payload) {
            if size > ioi_types::app::QUV_OUTBOX_MAX_PAYLOAD_BYTES_V0 {
                return Err(anyhow!("QUV payload exceeds rooted outbox byte profile"));
            }
            (
                quv,
                ioi_types::app::QUV_OUTBOX_RESERVED_BYTES_PER_RECIPIENT_V0,
            )
        } else {
            (
                normal,
                ioi_types::app::QUV_OUTBOX_NORMAL_BYTES_PER_RECIPIENT_V0,
            )
        };
        *used = used
            .checked_add(size)
            .ok_or_else(|| anyhow!("PQ outbox byte accounting overflow"))?;
        if *used > limit {
            return Err(anyhow!("PQ outbox recipient byte budget exhausted"));
        }
        Ok(())
    }
}
fn validate_outbox_byte_profile(entries: &[Arc<PqOutboxEntryV2>]) -> Result<()> {
    let mut usage = OutboxByteUsage::default();
    for entry in entries {
        usage.observe(entry.recipient_account_id, &entry.payload)?;
    }
    Ok(())
}

fn is_quv_payload(payload: &PqConsensusPayloadV1) -> bool {
    matches!(
        payload,
        PqConsensusPayloadV1::QuvPushQuery(_) | PqConsensusPayloadV1::QuvReply(_)
    )
}

/// Transport capability rooted by the local validator-set view. This does not
/// create consensus authority: it only constrains which already-authenticated
/// payload classes may cross one PQ session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PqChannelCapabilityV1 {
    /// Account belongs to the configuration named by `configuration_hash`.
    ConfiguredMember,
    /// Account belongs only to the canonically staged successor set. It may
    /// push a Q-EA7 handoff candidate to old members and receive their replies,
    /// but it cannot carry old-root consensus or ordinary effect traffic.
    HandoffOnlySuccessor,
}

#[derive(Clone)]
pub struct PqChannelLocalConfig {
    pub network_id: [u8; 32],
    pub configuration_hash: [u8; 32],
    pub epoch: u64,
    pub account_id: AccountId,
    pub peer_id: PeerId,
    pub identity: MldsaKeyPair,
    pub identity_key_hash: [u8; 32],
    /// Configuration-scoped durable outbox. A new configuration must use a
    /// different path so stale authority is never replayed after rotation.
    pub outbox_path: PathBuf,
    /// Complete independently rooted old/staged account scope, available before
    /// carrier discovery. This is not populated from provisional peer claims.
    pub rooted_accounts: std::collections::BTreeSet<AccountId>,
}

impl fmt::Debug for PqChannelLocalConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PqChannelLocalConfig")
            .field("network_id", &self.network_id)
            .field("configuration_hash", &self.configuration_hash)
            .field("epoch", &self.epoch)
            .field("account_id", &self.account_id)
            .field("peer_id", &self.peer_id)
            .field("identity", &"<redacted ML-DSA keypair>")
            .field("identity_key_hash", &self.identity_key_hash)
            .field("outbox_path", &self.outbox_path)
            .finish()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PqPeerEnrollment {
    pub peer_id: PeerId,
    pub account_id: AccountId,
    pub identity_key_hash: [u8; 32],
}

struct EstablishedSession {
    remote_account_id: AccountId,
    remote_capability: PqChannelCapabilityV1,
    transcript_hash: [u8; 32],
    application_ready: bool,
    completed_client_hello: Option<PqChannelClientHelloV1>,
    sealer: PqChannelRecordSealer,
    opener: PqChannelRecordOpener,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
struct PqOutboxEntryV2 {
    /// Rooted protocol identity, deliberately independent of the transient
    /// libp2p carrier. This permits durable enqueue before peer discovery.
    recipient_account_id: AccountId,
    message_id: [u8; 32],
    payload: PqConsensusPayloadV1,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
struct PqOutboxStateV2 {
    protocol_version: u16,
    schema_version: u16,
    network_id: [u8; 32],
    configuration_hash: [u8; 32],
    epoch: u64,
    local_account_id: AccountId,
    entries: Vec<Arc<PqOutboxEntryV2>>,
}

struct PqDurableOutbox {
    path: PathBuf,
    _lock: File,
    state: PqOutboxStateV2,
    persistence_failed: bool,
    indexed: bool,
    rooted_accounts: std::collections::BTreeSet<AccountId>,
}

fn outbox_lock_path(path: &Path) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(".lock");
    PathBuf::from(value)
}

fn outbox_temp_path(path: &Path) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(".tmp");
    PathBuf::from(value)
}

fn create_outbox_directory(path: &Path) -> Result<()> {
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(&path)?;
    // Sync each directory before its parent, including newly created ancestry.
    // Existing configured ancestry is trusted; unsupported durability fails.
    for ancestor in path.ancestors() {
        File::open(ancestor)?.sync_all()?;
    }
    Ok(())
}

fn open_private_file(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.create(true).read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
        .open(path)
        .map_err(|error| anyhow!("failed to open PQ outbox file {}: {error}", path.display()))
}

// SCALE's blanket Write adapter panics on I/O errors. Preserve the existing
// fallible persistence/quarantine contract while avoiding a whole-state buffer.
fn encode_outbox_to(state: &PqOutboxStateV2, writer: &mut impl Write) -> std::io::Result<()> {
    struct FallibleOutput<'a, W> {
        writer: &'a mut W,
        error: Option<std::io::Error>,
    }
    impl<W: Write> parity_scale_codec::Output for FallibleOutput<'_, W> {
        fn write(&mut self, bytes: &[u8]) {
            if self.error.is_none() {
                self.error = self.writer.write_all(bytes).err();
            }
        }
    }
    let mut output = FallibleOutput {
        writer,
        error: None,
    };
    state.encode_to(&mut output);
    match output.error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

fn persist_outbox(path: &Path, state: &PqOutboxStateV2) -> Result<()> {
    let temp = outbox_temp_path(path);
    let mut options = OpenOptions::new();
    options.create(true).truncate(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&temp)
        .map_err(|error| anyhow!("failed to stage PQ outbox {}: {error}", temp.display()))?;
    {
        let mut buffered = BufWriter::with_capacity(64 * 1024, &mut file);
        encode_outbox_to(state, &mut buffered)?;
        buffered.flush()?;
    }
    file.sync_all()?;
    std::fs::rename(&temp, path)?;
    if let Some(parent) = path.parent() {
        File::open(parent)?.sync_all()?;
    }
    Ok(())
}

impl PqDurableOutbox {
    fn open(local: &PqChannelLocalConfig) -> Result<Self> {
        let parent = local
            .outbox_path
            .parent()
            .ok_or_else(|| anyhow!("PQ outbox path must have a durable parent directory"))?;
        create_outbox_directory(parent)?;
        let lock = open_private_file(&outbox_lock_path(&local.outbox_path))?;
        fs2::FileExt::try_lock_exclusive(&lock).map_err(|error| {
            anyhow!(
                "PQ outbox {} is already owned by another process: {error}",
                local.outbox_path.display()
            )
        })?;
        let expected = PqOutboxStateV2 {
            protocol_version: PQ_OUTBOX_PROTOCOL_VERSION,
            schema_version: PQ_OUTBOX_SCHEMA_VERSION,
            network_id: local.network_id,
            configuration_hash: local.configuration_hash,
            epoch: local.epoch,
            local_account_id: local.account_id,
            entries: Vec::new(),
        };
        let indexed = local.outbox_path.exists() && outbox_index::is_index(&local.outbox_path)?;
        let state = if local.outbox_path.exists() {
            let decoded = if indexed {
                outbox_index::read(&local.outbox_path, &expected, &local.rooted_accounts)?
            } else {
                outbox_decode::read_outbox(&local.outbox_path, &expected, &local.rooted_accounts)?
            };
            if decoded.protocol_version != expected.protocol_version
                || decoded.schema_version != expected.schema_version
                || decoded.network_id != expected.network_id
                || decoded.configuration_hash != expected.configuration_hash
                || decoded.epoch != expected.epoch
                || decoded.local_account_id != expected.local_account_id
            {
                return Err(anyhow!(
                    "PQ outbox scope/version does not match the active configuration"
                ));
            }
            decoded
        } else {
            persist_outbox(&local.outbox_path, &expected)?;
            expected
        };
        let mut outbox = Self {
            path: local.outbox_path.clone(),
            _lock: lock,
            state,
            persistence_failed: false,
            indexed,
            rooted_accounts: local.rooted_accounts.clone(),
        };
        outbox.validate_entries()?;
        outbox_index::cleanup(&local.outbox_path, &outbox.state, indexed)?;
        if !indexed {
            // Complete validated v2 conversion before admitting live traffic.
            // A failed conversion leaves either the old snapshot or a complete
            // new index recoverable; no caller receives a usable handle.
            outbox_index::persist(&local.outbox_path, None, &outbox.state, None)?;
            outbox.indexed = true;
        }
        outbox_reservation::prepare(&local.outbox_path, local.rooted_accounts.len())?;
        let arena_active = outbox_index::uses_arena(&local.outbox_path)?;
        outbox_arena::prepare(
            &local.outbox_path,
            &outbox.state,
            &local.rooted_accounts,
            arena_active,
        )?;
        if !arena_active {
            outbox_index::persist(
                &local.outbox_path,
                None,
                &outbox.state,
                Some(&local.rooted_accounts),
            )?;
            outbox_index::cleanup(&local.outbox_path, &outbox.state, true)?;
        }
        Ok(outbox)
    }

    fn require_usable(&self) -> Result<()> {
        if self.persistence_failed {
            return Err(anyhow!(
                "PQ outbox persistence outcome is uncertain; reopen required"
            ));
        }
        Ok(())
    }

    fn commit(&mut self, next: PqOutboxStateV2) -> Result<()> {
        let previous = self.indexed.then(|| self.state.clone());
        let accounts = self.rooted_accounts.clone();
        self.commit_with(next, |path, next| {
            outbox_index::persist(path, previous.as_ref(), next, Some(&accounts))
        })?;
        self.indexed = true;
        Ok(())
    }

    fn commit_with(
        &mut self,
        next: PqOutboxStateV2,
        persist: impl FnOnce(&Path, &PqOutboxStateV2) -> Result<()>,
    ) -> Result<()> {
        self.require_usable()?;
        // Capacity refusal precedes all writes and does not quarantine healthy state.
        validate_outbox_byte_profile(&next.entries)?;
        // Rename may have succeeded before a later synchronization error.
        // Never continue from an in-memory snapshot whose disk outcome is unknown.
        if let Err(error) = persist(&self.path, &next) {
            if error.is::<outbox_index::NormalCapacityRefusal>() {
                return Err(error);
            }
            self.persistence_failed = true;
            return Err(error.context("PQ outbox persistence failed; reopen required"));
        }
        self.state = next;
        Ok(())
    }

    fn validate_entries(&self) -> Result<()> {
        validate_outbox_byte_profile(&self.state.entries)?;
        let mut seen = std::collections::BTreeSet::new();
        let mut per_recipient: HashMap<AccountId, usize> = HashMap::new();
        let mut normal_per_recipient: HashMap<AccountId, usize> = HashMap::new();
        for entry in &self.state.entries {
            if !self.rooted_accounts.contains(&entry.recipient_account_id) {
                return Err(anyhow!(
                    "PQ outbox recipient is outside rooted account scope"
                ));
            }
            if entry.recipient_account_id == self.state.local_account_id {
                return Err(anyhow!("PQ outbox contains a message to the local account"));
            }
            if self.message_id(entry.recipient_account_id, &entry.payload)? != entry.message_id {
                return Err(anyhow!(
                    "PQ outbox message commitment does not match its scoped payload"
                ));
            }
            if !seen.insert(entry.message_id) {
                return Err(anyhow!("PQ outbox repeats a message commitment"));
            }
            let count = per_recipient.entry(entry.recipient_account_id).or_default();
            *count += 1;
            if *count > PQ_OUTBOX_PER_RECIPIENT_MAX {
                return Err(anyhow!("PQ outbox exceeds the per-recipient durable limit"));
            }
            if !is_quv_payload(&entry.payload) {
                let normal = normal_per_recipient
                    .entry(entry.recipient_account_id)
                    .or_default();
                *normal += 1;
                if *normal > PQ_OUTBOX_NORMAL_PER_RECIPIENT_MAX {
                    return Err(anyhow!(
                        "PQ outbox exceeds the normal-traffic per-recipient durable limit"
                    ));
                }
            }
        }
        Ok(())
    }

    fn message_id(&self, recipient: AccountId, payload: &PqConsensusPayloadV1) -> Result<[u8; 32]> {
        if is_quv_payload(payload)
            && payload.encoded_size() as u64 > ioi_types::app::QUV_OUTBOX_MAX_PAYLOAD_BYTES_V0
        {
            return Err(anyhow!("QUV payload exceeds rooted outbox byte profile"));
        }
        // This is the exact plaintext encoding later passed to record sealing.
        // Reject before hashing, cloning state or persisting an unsendable entry.
        if payload.encoded_size() > PQ_CHANNEL_MAX_RECORD_PLAINTEXT_V1 {
            return Err(anyhow!(
                "PQ outbox payload exceeds the record plaintext limit"
            ));
        }
        let encoded = codec::to_bytes_canonical(&(
            PQ_OUTBOX_MESSAGE_ID_DOMAIN.to_vec(),
            self.state.network_id,
            self.state.configuration_hash,
            self.state.epoch,
            self.state.local_account_id,
            recipient,
            payload,
        ))
        .map_err(anyhow::Error::msg)?;
        ioi_crypto::algorithms::hash::sha256(&encoded).map_err(|error| anyhow!(error.to_string()))
    }

    fn enqueue_with_retired(
        &mut self,
        recipient: AccountId,
        payload: PqConsensusPayloadV1,
    ) -> Result<([u8; 32], std::collections::BTreeSet<[u8; 32]>)> {
        self.require_usable()?;
        if !self.rooted_accounts.contains(&recipient) {
            return Err(anyhow!(
                "PQ outbox recipient is outside rooted account scope"
            ));
        }
        if recipient == self.state.local_account_id {
            return Err(anyhow!("PQ outbox refuses a message to the local account"));
        }
        let message_id = self.message_id(recipient, &payload)?;
        if self
            .state
            .entries
            .iter()
            .any(|entry| entry.message_id == message_id)
        {
            return Ok((message_id, std::collections::BTreeSet::new()));
        }
        let mut next = self.state.clone();
        let mut retired = std::collections::BTreeSet::new();
        if matches!(payload, PqConsensusPayloadV1::QuvReply(_)) {
            // A reply is bound to one verifier nonce. Once the same requester
            // presents a later request, an older queued reply is no longer
            // useful to that request and cannot be allowed to pin reserved
            // capacity by withholding its transport ACK. Replace it and the
            // new reply in one durable transition so a crash loses neither.
            next.entries.retain(|entry| {
                let superseded = entry.recipient_account_id == recipient
                    && matches!(entry.payload, PqConsensusPayloadV1::QuvReply(_));
                if superseded {
                    retired.insert(entry.message_id);
                }
                !superseded
            });
        }
        let total_for_recipient = next
            .entries
            .iter()
            .filter(|entry| entry.recipient_account_id == recipient)
            .count();
        let normal_for_recipient = next
            .entries
            .iter()
            .filter(|entry| {
                entry.recipient_account_id == recipient && !is_quv_payload(&entry.payload)
            })
            .count();
        if total_for_recipient >= PQ_OUTBOX_PER_RECIPIENT_MAX
            || (!is_quv_payload(&payload)
                && normal_for_recipient >= PQ_OUTBOX_NORMAL_PER_RECIPIENT_MAX)
        {
            return Err(anyhow!(
                "PQ durable outbox is full for recipient; refusing to discard protected consensus evidence"
            ));
        }
        next.entries.push(Arc::new(PqOutboxEntryV2 {
            recipient_account_id: recipient,
            message_id,
            payload,
        }));
        self.commit(next)?;
        Ok((message_id, retired))
    }

    fn enqueue(&mut self, recipient: AccountId, payload: PqConsensusPayloadV1) -> Result<[u8; 32]> {
        self.enqueue_with_retired(recipient, payload)
            .map(|(message_id, _)| message_id)
    }

    fn front(&self, recipient: AccountId) -> Option<([u8; 32], PqConsensusPayloadV1)> {
        if self.persistence_failed {
            return None;
        }
        self.state
            .entries
            .iter()
            .find(|entry| entry.recipient_account_id == recipient && is_quv_payload(&entry.payload))
            .or_else(|| {
                self.state
                    .entries
                    .iter()
                    .find(|entry| entry.recipient_account_id == recipient)
            })
            .map(|entry| (entry.message_id, entry.payload.clone()))
    }

    fn acknowledge(&mut self, recipient: AccountId, message_id: [u8; 32]) -> Result<()> {
        self.require_usable()?;
        let index = self
            .state
            .entries
            .iter()
            .position(|entry| {
                entry.recipient_account_id == recipient && entry.message_id == message_id
            })
            .ok_or_else(|| anyhow!("PQ outbox acknowledgement does not name a pending message"))?;
        let mut next = self.state.clone();
        next.entries.remove(index);
        self.commit(next)?;
        Ok(())
    }

    fn retire_aft_async_instance(
        &mut self,
        instance_hash: [u8; 32],
    ) -> Result<std::collections::BTreeSet<[u8; 32]>> {
        self.require_usable()?;
        if instance_hash == [0; 32] {
            return Err(anyhow!("cannot retire an empty AFT async instance"));
        }
        let retired = self
            .state
            .entries
            .iter()
            .filter_map(|entry| match &entry.payload {
                PqConsensusPayloadV1::AftAsyncOrdering(bytes) => {
                    codec::from_bytes_canonical::<AftAsyncCarrierV1>(bytes)
                        .ok()
                        .filter(|carrier| carrier.instance_hash == instance_hash)
                        .map(|_| entry.message_id)
                }
                _ => None,
            })
            .collect::<std::collections::BTreeSet<_>>();
        if retired.is_empty() {
            return Ok(retired);
        }
        let mut next = self.state.clone();
        next.entries
            .retain(|entry| !retired.contains(&entry.message_id));
        self.commit(next)?;
        Ok(retired)
    }

    fn retire_quv_pushes_matching(
        &mut self,
        predicate: impl Fn(QuvNonce) -> bool,
    ) -> Result<std::collections::BTreeSet<[u8; 32]>> {
        let retired = self
            .state
            .entries
            .iter()
            .filter_map(|entry| match &entry.payload {
                PqConsensusPayloadV1::QuvPushQuery(bytes) => {
                    codec::from_bytes_canonical::<QuvPushQueryV0>(bytes)
                        .ok()
                        .filter(|query| predicate(query.verifier_nonce))
                        .map(|_| entry.message_id)
                }
                _ => None,
            })
            .collect::<std::collections::BTreeSet<_>>();
        self.retire_message_ids(&retired)?;
        Ok(retired)
    }

    fn retire_quv_pushes_except(
        &mut self,
        active_nonce: QuvNonce,
    ) -> Result<std::collections::BTreeSet<[u8; 32]>> {
        self.retire_quv_pushes_matching(|nonce| nonce != active_nonce)
    }

    fn retire_quv_pushes_for_operation(
        &mut self,
        nonce: QuvNonce,
    ) -> Result<std::collections::BTreeSet<[u8; 32]>> {
        self.retire_quv_pushes_matching(|candidate| candidate == nonce)
    }

    fn retire_quv_replies_for_recipient(
        &mut self,
        recipient: AccountId,
    ) -> Result<std::collections::BTreeSet<[u8; 32]>> {
        let retired = self
            .state
            .entries
            .iter()
            .filter(|entry| {
                entry.recipient_account_id == recipient
                    && matches!(entry.payload, PqConsensusPayloadV1::QuvReply(_))
            })
            .map(|entry| entry.message_id)
            .collect::<std::collections::BTreeSet<_>>();
        self.retire_message_ids(&retired)?;
        Ok(retired)
    }

    fn retire_message_ids(&mut self, retired: &std::collections::BTreeSet<[u8; 32]>) -> Result<()> {
        self.require_usable()?;
        if retired.is_empty() {
            return Ok(());
        }
        let mut next = self.state.clone();
        next.entries
            .retain(|entry| !retired.contains(&entry.message_id));
        self.commit(next)?;
        Ok(())
    }

    fn recipients(&self) -> Vec<AccountId> {
        if self.persistence_failed {
            return Vec::new();
        }
        let mut recipients = VecDeque::new();
        for entry in &self.state.entries {
            if !recipients.contains(&entry.recipient_account_id) {
                recipients.push_back(entry.recipient_account_id);
            }
        }
        recipients.into()
    }
}

pub struct PqChannelSessionManager {
    local: PqChannelLocalConfig,
    local_capability: PqChannelCapabilityV1,
    enrollments: HashMap<PeerId, PqPeerEnrollment>,
    peer_capabilities: HashMap<PeerId, PqChannelCapabilityV1>,
    pending_initiators: HashMap<PeerId, PqChannelInitiatorState>,
    pending_responders: HashMap<PeerId, PqChannelResponderState>,
    sessions: HashMap<PeerId, EstablishedSession>,
    authenticated_enrollments: std::collections::HashSet<PeerId>,
    provisional_enrollments: HashMap<PeerId, Instant>,
    outbox: PqDurableOutbox,
}

fn transport_binding(peer: &PeerId) -> Result<[u8; 32]> {
    ioi_crypto::algorithms::hash::sha256(peer.to_bytes())
        .map_err(|error| anyhow!(error.to_string()))
}

impl PqChannelSessionManager {
    pub fn new(local: PqChannelLocalConfig) -> Result<Self> {
        Self::new_with_capability(local, PqChannelCapabilityV1::ConfiguredMember)
    }

    /// Construct a transport endpoint for a canonically staged successor that
    /// has no authority in the configuration naming this channel scope.
    pub fn new_handoff_only(local: PqChannelLocalConfig) -> Result<Self> {
        Self::new_with_capability(local, PqChannelCapabilityV1::HandoffOnlySuccessor)
    }

    fn new_with_capability(
        local: PqChannelLocalConfig,
        local_capability: PqChannelCapabilityV1,
    ) -> Result<Self> {
        if local.configuration_hash == [0; 32] {
            return Err(anyhow!("PQ channel configuration hash is absent"));
        }
        if !local.rooted_accounts.contains(&local.account_id) {
            return Err(anyhow!("PQ local account is outside rooted account scope"));
        }
        let outbox = PqDurableOutbox::open(&local)?;
        Ok(Self {
            local,
            local_capability,
            enrollments: HashMap::new(),
            peer_capabilities: HashMap::new(),
            pending_initiators: HashMap::new(),
            pending_responders: HashMap::new(),
            sessions: HashMap::new(),
            authenticated_enrollments: std::collections::HashSet::new(),
            provisional_enrollments: HashMap::new(),
            outbox,
        })
    }

    /// Installs provisional rooted peer metadata. An authenticated enrollment
    /// can change only through explicit configuration/manager replacement.
    pub fn enroll_peer(&mut self, enrollment: PqPeerEnrollment) -> Result<()> {
        self.enroll_peer_with_capability(enrollment, PqChannelCapabilityV1::ConfiguredMember)
    }

    /// Admit a canonically staged successor for handoff traffic only. The
    /// caller must derive this classification from the rooted successor set.
    pub fn enroll_handoff_peer(&mut self, enrollment: PqPeerEnrollment) -> Result<()> {
        self.enroll_peer_with_capability(enrollment, PqChannelCapabilityV1::HandoffOnlySuccessor)
    }

    fn enroll_peer_with_capability(
        &mut self,
        enrollment: PqPeerEnrollment,
        capability: PqChannelCapabilityV1,
    ) -> Result<()> {
        if !self.local.rooted_accounts.contains(&enrollment.account_id) {
            return Err(anyhow!("PQ peer is outside rooted account scope"));
        }
        self.expire_provisional_enrollments();
        if enrollment.peer_id == self.local.peer_id
            || enrollment.account_id == self.local.account_id
        {
            return Err(anyhow!("PQ peer enrollment aliases the local endpoint"));
        }
        // Status synchronization refreshes rooted peer metadata repeatedly.
        // Treat an identical refresh as idempotent: tearing down an established
        // or in-flight session here can indefinitely suppress strict-PQ traffic
        // while status responses continue to arrive.
        if self.enrollments.get(&enrollment.peer_id) == Some(&enrollment)
            && self.peer_capabilities.get(&enrollment.peer_id) == Some(&capability)
        {
            return Ok(());
        }
        if self.authenticated_enrollments.contains(&enrollment.peer_id) {
            return Err(anyhow!(
                "PQ authenticated enrollment change requires reconfiguration"
            ));
        }
        if self.enrollments.iter().any(|(peer, existing)| {
            *peer != enrollment.peer_id
                && existing.account_id == enrollment.account_id
                && self.sessions.contains_key(peer)
        }) {
            return Err(anyhow!(
                "PQ peer enrollment conflicts with an authenticated carrier for the rooted account"
            ));
        }
        let is_new = !self
            .provisional_enrollments
            .contains_key(&enrollment.peer_id);
        let aliases = self
            .provisional_enrollments
            .keys()
            .filter(|peer| {
                **peer != enrollment.peer_id
                    && self
                        .enrollments
                        .get(peer)
                        .is_some_and(|existing| existing.account_id == enrollment.account_id)
            })
            .count();
        if (is_new && self.provisional_enrollments.len() >= PQ_PROVISIONAL_ENROLLMENTS_MAX)
            || aliases >= PQ_PROVISIONAL_PER_ACCOUNT_MAX
        {
            return Err(anyhow!("PQ provisional enrollment capacity exceeded"));
        }
        let admitted_at = self
            .provisional_enrollments
            .get(&enrollment.peer_id)
            .copied()
            .unwrap_or_else(Instant::now);
        self.authenticated_enrollments.remove(&enrollment.peer_id);
        self.disconnect(&enrollment.peer_id);
        self.peer_capabilities
            .insert(enrollment.peer_id, capability);
        self.provisional_enrollments
            .insert(enrollment.peer_id, admitted_at);
        self.enrollments.insert(enrollment.peer_id, enrollment);
        Ok(())
    }

    /// Unproved status metadata cannot retain enrollment or ephemeral key
    /// state indefinitely. Identical refreshes do not extend this lifetime.
    pub fn expire_provisional_enrollments(&mut self) {
        let now = Instant::now();
        let expired = self
            .provisional_enrollments
            .iter()
            .filter_map(|(peer, admitted)| {
                (now.saturating_duration_since(*admitted) >= PQ_PROVISIONAL_ENROLLMENT_LIFETIME)
                    .then_some(*peer)
            })
            .collect::<Vec<_>>();
        for peer in expired {
            self.disconnect(&peer);
        }
    }

    fn enrollment(&self, peer: &PeerId) -> Result<&PqPeerEnrollment> {
        if self
            .provisional_enrollments
            .get(peer)
            .is_some_and(|admitted| admitted.elapsed() >= PQ_PROVISIONAL_ENROLLMENT_LIFETIME)
        {
            return Err(anyhow!("PQ provisional enrollment expired"));
        }
        self.enrollments
            .get(peer)
            .ok_or_else(|| anyhow!("peer has no rooted PQ channel enrollment"))
    }

    fn scope_as_initiator(&self, remote: &PqPeerEnrollment) -> Result<PqChannelScopeV1> {
        Ok(PqChannelScopeV1 {
            network_id: self.local.network_id,
            configuration_hash: self.local.configuration_hash,
            epoch: self.local.epoch,
            initiator: self.local.account_id,
            responder: remote.account_id,
            initiator_transport_binding: transport_binding(&self.local.peer_id)?,
            responder_transport_binding: transport_binding(&remote.peer_id)?,
        })
    }

    fn scope_as_responder(&self, remote: &PqPeerEnrollment) -> Result<PqChannelScopeV1> {
        Ok(PqChannelScopeV1 {
            network_id: self.local.network_id,
            configuration_hash: self.local.configuration_hash,
            epoch: self.local.epoch,
            initiator: remote.account_id,
            responder: self.local.account_id,
            initiator_transport_binding: transport_binding(&remote.peer_id)?,
            responder_transport_binding: transport_binding(&self.local.peer_id)?,
        })
    }

    pub fn start(&mut self, peer: PeerId) -> Result<PqChannelClientHelloV1> {
        self.expire_provisional_enrollments();
        if !self.should_initiate(&peer) {
            return Err(anyhow!(
                "local endpoint is not the deterministic PQ channel initiator"
            ));
        }
        if self.sessions.contains_key(&peer)
            || self.pending_initiators.contains_key(&peer)
            || self.pending_responders.contains_key(&peer)
        {
            return Err(anyhow!(
                "PQ channel already established or pending for peer"
            ));
        }
        let remote = self.enrollment(&peer)?.clone();
        let (state, hello) = start_pq_channel(
            self.scope_as_initiator(&remote)?,
            &self.local.identity,
            remote.identity_key_hash,
        )?;
        self.pending_initiators.insert(peer, state);
        Ok(hello)
    }

    pub fn accept(
        &mut self,
        peer: PeerId,
        hello: PqChannelClientHelloV1,
    ) -> Result<PqChannelServerHelloV1> {
        self.expire_provisional_enrollments();
        if self.should_initiate(&peer) {
            return Err(anyhow!(
                "remote endpoint is not the deterministic PQ channel initiator"
            ));
        }
        if self
            .sessions
            .get(&peer)
            .is_some_and(|session| session.completed_client_hello.as_ref() == Some(&hello))
        {
            return Err(anyhow!(
                "PQ responder refused a replay of the completed client hello"
            ));
        }
        if let Some(state) = self.pending_responders.get(&peer) {
            if let Some(response) = state.response_for_retry(&hello) {
                return Ok(response);
            }
        }
        let remote = self.enrollment(&peer)?.clone();
        let (state, server) = accept_pq_channel(
            &self.scope_as_responder(&remote)?,
            remote.identity_key_hash,
            self.local.identity_key_hash,
            &self.local.identity,
            hello,
        )?;
        // A different, fully authenticated hello proves that the deterministic
        // initiator abandoned the earlier carrier transcript. Replace pending
        // or established ephemeral state only after validating the new hello.
        self.sessions.remove(&peer);
        self.pending_responders.insert(peer, state);
        Ok(server)
    }

    pub fn finish(
        &mut self,
        peer: PeerId,
        server: PqChannelServerHelloV1,
    ) -> Result<PqChannelClientFinishV1> {
        self.expire_provisional_enrollments();
        let pending = self
            .pending_initiators
            .get(&peer)
            .ok_or_else(|| anyhow!("no pending PQ initiator state for peer"))?;
        if !pending.accepts_server_hello(&server)? {
            return Err(anyhow!(
                "PQ channel server hello binds another client hello"
            ));
        }
        let state = self
            .pending_initiators
            .remove(&peer)
            .expect("pending initiator was checked above");
        let remote = self.enrollment(&peer)?.clone();
        let (finish, keys) = finish_pq_channel(state, server)?;
        let transcript_hash = keys.transcript_hash();
        self.sessions.insert(
            peer,
            EstablishedSession {
                remote_account_id: remote.account_id,
                remote_capability: self
                    .peer_capabilities
                    .get(&peer)
                    .copied()
                    .ok_or_else(|| anyhow!("peer has no rooted PQ capability"))?,
                transcript_hash,
                application_ready: false,
                completed_client_hello: None,
                sealer: PqChannelRecordSealer::new(
                    transcript_hash,
                    PqChannelDirectionV1::InitiatorToResponder,
                    keys.initiator_to_responder(),
                ),
                opener: PqChannelRecordOpener::new(
                    transcript_hash,
                    PqChannelDirectionV1::ResponderToInitiator,
                    keys.responder_to_initiator(),
                ),
            },
        );
        Ok(finish)
    }

    pub fn complete(&mut self, peer: PeerId, finish: PqChannelClientFinishV1) -> Result<()> {
        self.expire_provisional_enrollments();
        if self
            .sessions
            .get(&peer)
            .is_some_and(|session| session.transcript_hash == finish.transcript_hash)
        {
            return Ok(());
        }
        let pending = self
            .pending_responders
            .get(&peer)
            .ok_or_else(|| anyhow!("no pending PQ responder state for peer"))?;
        if !pending.accepts_finish(&finish)? {
            return Err(anyhow!("PQ channel finish transcript mismatch"));
        }
        let completed_client_hello = pending.client_hello_for_replay_guard().clone();
        let state = self
            .pending_responders
            .remove(&peer)
            .expect("pending responder was checked above");
        let remote = self.enrollment(&peer)?.clone();
        let keys = complete_pq_channel(state, finish)?;
        let transcript_hash = keys.transcript_hash();
        self.sessions.insert(
            peer,
            EstablishedSession {
                remote_account_id: remote.account_id,
                remote_capability: self
                    .peer_capabilities
                    .get(&peer)
                    .copied()
                    .ok_or_else(|| anyhow!("peer has no rooted PQ capability"))?,
                transcript_hash,
                application_ready: true,
                completed_client_hello: Some(completed_client_hello),
                sealer: PqChannelRecordSealer::new(
                    transcript_hash,
                    PqChannelDirectionV1::ResponderToInitiator,
                    keys.responder_to_initiator(),
                ),
                opener: PqChannelRecordOpener::new(
                    transcript_hash,
                    PqChannelDirectionV1::InitiatorToResponder,
                    keys.initiator_to_responder(),
                ),
            },
        );
        self.authenticate_carrier(peer)?;
        Ok(())
    }

    pub fn is_established(&self, peer: &PeerId) -> bool {
        self.sessions.contains_key(peer)
    }

    pub fn is_application_ready(&self, peer: &PeerId) -> bool {
        self.sessions
            .get(peer)
            .is_some_and(|session| session.application_ready)
    }

    /// Opens initiator-side issuance only after the responder acknowledges
    /// authenticated key confirmation. Repeated acknowledgements are safe.
    pub fn confirm_application_ready(&mut self, peer: &PeerId) -> Result<()> {
        self.expire_provisional_enrollments();
        let session = self
            .sessions
            .get_mut(peer)
            .ok_or_else(|| anyhow!("PQ channel has no established keys for peer"))?;
        session.application_ready = true;
        self.authenticate_carrier(*peer)?;
        Ok(())
    }

    fn authenticate_carrier(&mut self, peer: PeerId) -> Result<()> {
        let account = self
            .sessions
            .get(&peer)
            .filter(|session| session.application_ready)
            .map(|session| session.remote_account_id)
            .ok_or_else(|| anyhow!("PQ carrier is not application-ready"))?;
        self.authenticated_enrollments.insert(peer);
        self.provisional_enrollments.remove(&peer);
        let aliases = self
            .enrollments
            .iter()
            .filter_map(|(candidate, enrollment)| {
                (*candidate != peer && enrollment.account_id == account).then_some(*candidate)
            })
            .collect::<Vec<_>>();
        for alias in aliases {
            self.pending_initiators.remove(&alias);
            self.pending_responders.remove(&alias);
            self.sessions.remove(&alias);
            self.authenticated_enrollments.remove(&alias);
            self.peer_capabilities.remove(&alias);
            self.enrollments.remove(&alias);
            self.provisional_enrollments.remove(&alias);
        }
        Ok(())
    }

    pub fn enrolled_peers(&self) -> impl Iterator<Item = PeerId> + '_ {
        self.enrollments.keys().copied()
    }

    /// Exactly one side initiates, preventing competing handshakes from
    /// replacing each other's traffic keys.
    pub fn should_initiate(&self, peer: &PeerId) -> bool {
        self.local.peer_id.to_bytes() < peer.to_bytes()
    }

    pub fn remote_account(&self, peer: &PeerId) -> Option<AccountId> {
        self.sessions
            .get(peer)
            .map(|session| session.remote_account_id)
    }

    /// Enforce the receiver's independently rooted view of both endpoint
    /// capabilities after AEAD and identity authentication, before decoding
    /// can reach any consensus or QUV handler.
    pub fn permits_received_payload(&self, peer: &PeerId, payload: &PqConsensusPayloadV1) -> bool {
        let Some(session) = self.sessions.get(peer) else {
            return false;
        };
        match (self.local_capability, session.remote_capability) {
            (PqChannelCapabilityV1::ConfiguredMember, PqChannelCapabilityV1::ConfiguredMember) => {
                true
            }
            (
                PqChannelCapabilityV1::ConfiguredMember,
                PqChannelCapabilityV1::HandoffOnlySuccessor,
            ) => matches!(payload, PqConsensusPayloadV1::QuvPushQuery(_)),
            (
                PqChannelCapabilityV1::HandoffOnlySuccessor,
                PqChannelCapabilityV1::ConfiguredMember,
            ) => matches!(payload, PqConsensusPayloadV1::QuvReply(_)),
            (
                PqChannelCapabilityV1::HandoffOnlySuccessor,
                PqChannelCapabilityV1::HandoffOnlySuccessor,
            ) => false,
        }
    }

    /// Sender-side mirror of `permits_received_payload`. Filtering at enqueue
    /// keeps old-root consensus broadcasts out of successor-only durable
    /// outboxes instead of relying on the remote endpoint to reject them.
    pub fn permits_sent_payload(&self, peer: &PeerId, payload: &PqConsensusPayloadV1) -> bool {
        let Some(remote_capability) = self.peer_capabilities.get(peer).copied() else {
            return false;
        };
        match (self.local_capability, remote_capability) {
            (PqChannelCapabilityV1::ConfiguredMember, PqChannelCapabilityV1::ConfiguredMember) => {
                true
            }
            (
                PqChannelCapabilityV1::ConfiguredMember,
                PqChannelCapabilityV1::HandoffOnlySuccessor,
            ) => matches!(payload, PqConsensusPayloadV1::QuvReply(_)),
            (
                PqChannelCapabilityV1::HandoffOnlySuccessor,
                PqChannelCapabilityV1::ConfiguredMember,
            ) => matches!(payload, PqConsensusPayloadV1::QuvPushQuery(_)),
            (
                PqChannelCapabilityV1::HandoffOnlySuccessor,
                PqChannelCapabilityV1::HandoffOnlySuccessor,
            ) => false,
        }
    }

    pub fn peer_for_account(&self, account: AccountId) -> Option<PeerId> {
        self.enrollments.iter().find_map(|(peer, enrollment)| {
            (enrollment.account_id == account && self.is_application_ready(peer)).then_some(*peer)
        })
    }

    /// Durably queues for a rooted account before its transient carrier is
    /// necessarily known. Enrollment later makes the entry drainable.
    pub fn enqueue_for_account(
        &mut self,
        recipient: AccountId,
        payload: PqConsensusPayloadV1,
    ) -> Result<[u8; 32]> {
        if self.local_capability == PqChannelCapabilityV1::HandoffOnlySuccessor
            && !matches!(payload, PqConsensusPayloadV1::QuvPushQuery(_))
        {
            return Err(anyhow!(
                "handoff-only PQ endpoint may send only QUV PUSHQUERY traffic"
            ));
        }
        self.outbox.enqueue(recipient, payload)
    }

    pub fn enqueue_quv_reply_for_account(
        &mut self,
        recipient: AccountId,
        payload: PqConsensusPayloadV1,
    ) -> Result<([u8; 32], std::collections::BTreeSet<[u8; 32]>)> {
        if !matches!(payload, PqConsensusPayloadV1::QuvReply(_)) {
            return Err(anyhow!("QUV reply enqueue requires a QUV reply payload"));
        }
        if self.local_capability == PqChannelCapabilityV1::HandoffOnlySuccessor {
            return Err(anyhow!("handoff-only PQ endpoint may not send QUV replies"));
        }
        self.outbox.enqueue_with_retired(recipient, payload)
    }

    pub fn enqueue(&mut self, peer: PeerId, payload: PqConsensusPayloadV1) -> Result<[u8; 32]> {
        if !self.permits_sent_payload(&peer, &payload) {
            return Err(anyhow!(
                "PQ payload exceeds the rooted local/remote endpoint capabilities"
            ));
        }
        let recipient = self.enrollment(&peer)?.account_id;
        self.enqueue_for_account(recipient, payload)
    }

    pub fn pending_front(&self, peer: &PeerId) -> Option<([u8; 32], PqConsensusPayloadV1)> {
        let recipient = self.enrollment(peer).ok()?.account_id;
        self.outbox.front(recipient)
    }

    pub fn acknowledge(&mut self, peer: &PeerId, message_id: [u8; 32]) -> Result<()> {
        let recipient = self.enrollment(peer)?.account_id;
        self.outbox.acknowledge(recipient, message_id)
    }

    /// Compacts durable data for one cryptographically completed hash-async
    /// instance without touching evidence for any other instance or class.
    pub fn retire_aft_async_instance(
        &mut self,
        instance_hash: [u8; 32],
    ) -> Result<std::collections::BTreeSet<[u8; 32]>> {
        self.outbox.retire_aft_async_instance(instance_hash)
    }

    /// Retire crash-recovered requests from verifier operations other than the
    /// newly admitted nonce. A stale request cannot authorize anything after
    /// its process-local decision interval and must not consume QUV reserve.
    pub fn retire_stale_quv_pushes(
        &mut self,
        active_nonce: QuvNonce,
    ) -> Result<std::collections::BTreeSet<[u8; 32]>> {
        self.outbox.retire_quv_pushes_except(active_nonce)
    }

    /// Retire all durable requests for a completed or aborted verifier
    /// operation, including requests whose Byzantine recipient withheld ACK.
    pub fn retire_quv_operation(
        &mut self,
        nonce: QuvNonce,
    ) -> Result<std::collections::BTreeSet<[u8; 32]>> {
        self.outbox.retire_quv_pushes_for_operation(nonce)
    }

    /// A new durable response to the same requester supersedes older
    /// nonce-bound snapshots. Those older replies cannot authorize the new
    /// operation and retaining them would let ACK withholding exhaust reserve.
    pub fn retire_quv_replies_for_recipient(
        &mut self,
        recipient: AccountId,
    ) -> Result<std::collections::BTreeSet<[u8; 32]>> {
        self.outbox.retire_quv_replies_for_recipient(recipient)
    }

    pub fn pending_peers(&self) -> Vec<PeerId> {
        self.outbox
            .recipients()
            .into_iter()
            .filter_map(|recipient| self.peer_for_account(recipient))
            .collect()
    }

    pub fn seal(
        &mut self,
        peer: &PeerId,
        content_type: PqChannelContentTypeV1,
        plaintext: &[u8],
    ) -> Result<PqChannelRecordV1> {
        let session = self
            .sessions
            .get_mut(peer)
            .ok_or_else(|| anyhow!("PQ channel is not established for peer"))?;
        if !session.application_ready {
            return Err(anyhow!(
                "PQ channel finish is not acknowledged for application traffic"
            ));
        }
        session.sealer.seal(content_type, plaintext)
    }

    pub fn open(&mut self, peer: &PeerId, record: &PqChannelRecordV1) -> Result<Vec<u8>> {
        self.sessions
            .get_mut(peer)
            .ok_or_else(|| anyhow!("PQ channel is not established for peer"))?
            .opener
            .open(record)
    }

    pub fn disconnect(&mut self, peer: &PeerId) {
        let authenticated = self.authenticated_enrollments.contains(peer);
        self.pending_initiators.remove(peer);
        self.pending_responders.remove(peer);
        self.sessions.remove(peer);
        if !authenticated {
            self.peer_capabilities.remove(peer);
            self.enrollments.remove(peer);
            self.provisional_enrollments.remove(peer);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ioi_api::crypto::{SerializableKey, SigningKeyPair};
    use ioi_crypto::security::SecurityLevel;
    use ioi_crypto::sign::dilithium::MldsaScheme;
    use ioi_types::app::{
        account_id_from_key_material, aft_async_proposal_payload_hash, AftAsyncCarrierBodyV1,
        AftAsyncProposalDescriptorV1, QuvAuthorityModeV0, QuvCandidateV0, QuvReplyV0, QuvSlotV0,
        SignatureSuite, AFT_ASYNC_PROTOCOL_VERSION_V1, AFT_ASYNC_SCHEMA_VERSION_V1,
    };
    use libp2p::identity::Keypair;

    fn local_config(account: u8, outbox_path: PathBuf) -> PqChannelLocalConfig {
        let identity = MldsaScheme::new(SecurityLevel::Level2)
            .generate_keypair()
            .unwrap();
        let identity_key_hash = account_id_from_key_material(
            SignatureSuite::ML_DSA_44,
            &identity.public_key().to_bytes(),
        )
        .unwrap();
        PqChannelLocalConfig {
            network_id: [1; 32],
            configuration_hash: [2; 32],
            epoch: 3,
            account_id: AccountId([account; 32]),
            peer_id: Keypair::generate_ed25519().public().to_peer_id(),
            identity,
            identity_key_hash,
            outbox_path,
            rooted_accounts: (0..=255).map(|id| AccountId([id; 32])).collect(),
        }
    }

    fn quv_query(nonce: u8, authorizer: AccountId) -> QuvPushQueryV0 {
        QuvPushQueryV0 {
            verifier_nonce: [nonce; 32],
            candidate: QuvCandidateV0 {
                slot: QuvSlotV0 {
                    configuration_root: [2; 32],
                    policy_root: [3; 32],
                    network_id: [1; 32],
                    domain_id: [4; 32],
                    slot: 1,
                    predecessor: [5; 32],
                    authority_mode: QuvAuthorityModeV0::Owned,
                },
                payload_hash: [6; 32],
                authorizer,
                authority_signature: vec![7],
            },
        }
    }

    fn quv_reply(nonce: u8, member: AccountId) -> QuvReplyV0 {
        let query = quv_query(nonce, member);
        QuvReplyV0 {
            verifier_nonce: query.verifier_nonce,
            member,
            slot: query.candidate.slot.clone(),
            candidate_hash: [8; 32],
            snapshot_hash: [9; 32],
            complete_snapshot: vec![query.candidate],
            signature: vec![10],
        }
    }

    #[test]
    fn managers_establish_and_gate_confidential_ordered_records() {
        let temp = tempfile::tempdir().unwrap();
        let mut a_config = local_config(10, temp.path().join("a.outbox"));
        let mut b_config = local_config(11, temp.path().join("b.outbox"));
        if a_config.peer_id.to_bytes() > b_config.peer_id.to_bytes() {
            std::mem::swap(&mut a_config, &mut b_config);
        }
        let a_peer = a_config.peer_id;
        let b_peer = b_config.peer_id;
        let a_enrollment = PqPeerEnrollment {
            peer_id: a_peer,
            account_id: a_config.account_id,
            identity_key_hash: a_config.identity_key_hash,
        };
        let b_enrollment = PqPeerEnrollment {
            peer_id: b_peer,
            account_id: b_config.account_id,
            identity_key_hash: b_config.identity_key_hash,
        };
        let mut a = PqChannelSessionManager::new(a_config).unwrap();
        let mut b = PqChannelSessionManager::new(b_config).unwrap();
        a.enroll_peer(b_enrollment).unwrap();
        b.enroll_peer(a_enrollment).unwrap();

        let hello = a.start(b_peer).unwrap();
        let server = b.accept(a_peer, hello).unwrap();
        let finish = a.finish(b_peer, server).unwrap();
        b.complete(a_peer, finish).unwrap();
        a.confirm_application_ready(&b_peer).unwrap();
        assert!(a.is_established(&b_peer));
        assert!(b.is_established(&a_peer));

        let record = a
            .seal(
                &b_peer,
                PqChannelContentTypeV1::ConsensusVote,
                b"signed vote",
            )
            .unwrap();
        assert_eq!(b.open(&a_peer, &record).unwrap(), b"signed vote");
        assert!(b.open(&a_peer, &record).is_err());
    }

    #[test]
    fn handoff_only_successor_is_cryptographically_connected_but_authority_isolated() {
        let temp = tempfile::tempdir().unwrap();
        let old_config = local_config(70, temp.path().join("old-member.outbox"));
        let successor_config = local_config(71, temp.path().join("successor-only.outbox"));
        let old_peer = old_config.peer_id;
        let successor_peer = successor_config.peer_id;
        let old_account = old_config.account_id;
        let successor_account = successor_config.account_id;
        let old_enrollment = PqPeerEnrollment {
            peer_id: old_peer,
            account_id: old_account,
            identity_key_hash: old_config.identity_key_hash,
        };
        let successor_enrollment = PqPeerEnrollment {
            peer_id: successor_peer,
            account_id: successor_account,
            identity_key_hash: successor_config.identity_key_hash,
        };
        let mut old = PqChannelSessionManager::new(old_config).unwrap();
        let mut successor = PqChannelSessionManager::new_handoff_only(successor_config).unwrap();
        old.enroll_handoff_peer(successor_enrollment).unwrap();
        successor.enroll_peer(old_enrollment).unwrap();

        if old.should_initiate(&successor_peer) {
            let hello = old.start(successor_peer).unwrap();
            let server = successor.accept(old_peer, hello).unwrap();
            let finish = old.finish(successor_peer, server).unwrap();
            successor.complete(old_peer, finish).unwrap();
            old.confirm_application_ready(&successor_peer).unwrap();
        } else {
            let hello = successor.start(old_peer).unwrap();
            let server = old.accept(successor_peer, hello).unwrap();
            let finish = successor.finish(old_peer, server).unwrap();
            old.complete(successor_peer, finish).unwrap();
            successor.confirm_application_ready(&old_peer).unwrap();
        }

        let push = PqConsensusPayloadV1::QuvPushQuery(vec![1]);
        let reply = PqConsensusPayloadV1::QuvReply(vec![2]);
        let vote = PqConsensusPayloadV1::Vote(vec![3]);
        assert!(old.permits_received_payload(&successor_peer, &push));
        assert!(!old.permits_received_payload(&successor_peer, &reply));
        assert!(!old.permits_received_payload(&successor_peer, &vote));
        assert!(successor.permits_received_payload(&old_peer, &reply));
        assert!(!successor.permits_received_payload(&old_peer, &push));
        assert!(!successor.permits_received_payload(&old_peer, &vote));
        assert!(old.permits_sent_payload(&successor_peer, &reply));
        assert!(!old.permits_sent_payload(&successor_peer, &push));
        assert!(!old.permits_sent_payload(&successor_peer, &vote));
        assert!(successor.permits_sent_payload(&old_peer, &push));
        assert!(!successor.permits_sent_payload(&old_peer, &reply));
        assert!(!successor.permits_sent_payload(&old_peer, &vote));
        assert!(successor.enqueue_for_account(old_account, push).is_ok());
        assert!(successor.enqueue_for_account(old_account, reply).is_err());
        assert!(successor.enqueue_for_account(old_account, vote).is_err());
    }

    #[test]
    fn identical_enrollment_refresh_preserves_established_session() {
        let temp = tempfile::tempdir().unwrap();
        let mut a_config = local_config(12, temp.path().join("a-refresh.outbox"));
        let mut b_config = local_config(13, temp.path().join("b-refresh.outbox"));
        if a_config.peer_id.to_bytes() > b_config.peer_id.to_bytes() {
            std::mem::swap(&mut a_config, &mut b_config);
        }
        let a_peer = a_config.peer_id;
        let b_peer = b_config.peer_id;
        let a_enrollment = PqPeerEnrollment {
            peer_id: a_peer,
            account_id: a_config.account_id,
            identity_key_hash: a_config.identity_key_hash,
        };
        let b_enrollment = PqPeerEnrollment {
            peer_id: b_peer,
            account_id: b_config.account_id,
            identity_key_hash: b_config.identity_key_hash,
        };
        let mut a = PqChannelSessionManager::new(a_config).unwrap();
        let mut b = PqChannelSessionManager::new(b_config).unwrap();
        a.enroll_peer(b_enrollment.clone()).unwrap();
        b.enroll_peer(a_enrollment.clone()).unwrap();

        let hello = a.start(b_peer).unwrap();
        let server = b.accept(a_peer, hello).unwrap();
        let finish = a.finish(b_peer, server).unwrap();
        b.complete(a_peer, finish).unwrap();
        a.confirm_application_ready(&b_peer).unwrap();

        a.enroll_peer(b_enrollment).unwrap();
        b.enroll_peer(a_enrollment).unwrap();
        assert!(a.is_established(&b_peer));
        assert!(b.is_established(&a_peer));

        let record = a
            .seal(
                &b_peer,
                PqChannelContentTypeV1::ConsensusVote,
                b"vote after metadata refresh",
            )
            .unwrap();
        assert_eq!(
            b.open(&a_peer, &record).unwrap(),
            b"vote after metadata refresh"
        );
    }

    #[test]
    fn delayed_server_hello_cannot_destroy_current_handshake() {
        let temp = tempfile::tempdir().unwrap();
        let mut a_config = local_config(14, temp.path().join("a-stale.outbox"));
        let mut b_config = local_config(15, temp.path().join("b-stale.outbox"));
        if a_config.peer_id.to_bytes() > b_config.peer_id.to_bytes() {
            std::mem::swap(&mut a_config, &mut b_config);
        }
        let a_peer = a_config.peer_id;
        let b_peer = b_config.peer_id;
        let a_enrollment = PqPeerEnrollment {
            peer_id: a_peer,
            account_id: a_config.account_id,
            identity_key_hash: a_config.identity_key_hash,
        };
        let b_enrollment = PqPeerEnrollment {
            peer_id: b_peer,
            account_id: b_config.account_id,
            identity_key_hash: b_config.identity_key_hash,
        };
        let mut a = PqChannelSessionManager::new(a_config).unwrap();
        let mut b = PqChannelSessionManager::new(b_config).unwrap();
        a.enroll_peer(b_enrollment.clone()).unwrap();
        b.enroll_peer(a_enrollment).unwrap();

        let old_hello = a.start(b_peer).unwrap();
        let old_server = b.accept(a_peer, old_hello).unwrap();

        // Model both endpoints observing a carrier disconnect and starting a
        // fresh transcript while the old response is still in an event queue.
        a.disconnect(&b_peer);
        a.enroll_peer(b_enrollment).unwrap();
        let current_hello = a.start(b_peer).unwrap();
        let current_server = b.accept(a_peer, current_hello.clone()).unwrap();

        assert!(a.finish(b_peer, old_server).is_err());
        // An exact request retransmission receives the cached response and
        // does not replace the responder's pending KEM state.
        assert_eq!(
            b.accept(a_peer, current_hello.clone()).unwrap(),
            current_server
        );
        let finish = a.finish(b_peer, current_server).unwrap();
        assert!(!a.is_application_ready(&b_peer));
        assert!(a
            .seal(
                &b_peer,
                PqChannelContentTypeV1::ConsensusVote,
                b"must wait for finish acknowledgement",
            )
            .is_err());
        b.complete(a_peer, finish.clone()).unwrap();
        a.confirm_application_ready(&b_peer).unwrap();
        // A lost ACK can cause the same authenticated finish to be retried.
        b.complete(a_peer, finish).unwrap();
        // A delayed copy of the completed hello cannot replace the live keys.
        assert!(b.accept(a_peer, current_hello).is_err());

        // If the finish ACK was truly lost, the initiator abandons its
        // unconfirmed session and starts a new authenticated transcript. The
        // responder accepts that distinct hello and both sides converge again.
        a.disconnect(&b_peer);
        let recovery_hello = a.start(b_peer).unwrap();
        let recovery_server = b.accept(a_peer, recovery_hello).unwrap();
        let recovery_finish = a.finish(b_peer, recovery_server).unwrap();
        b.complete(a_peer, recovery_finish).unwrap();
        a.confirm_application_ready(&b_peer).unwrap();
        assert!(a.is_established(&b_peer));
        assert!(b.is_established(&a_peer));
    }

    #[test]
    fn configuration_rotation_invalidates_old_session_records() {
        let temp = tempfile::tempdir().unwrap();
        let mut a_config = local_config(30, temp.path().join("a-old.outbox"));
        let mut b_config = local_config(31, temp.path().join("b-old.outbox"));
        if a_config.peer_id.to_bytes() > b_config.peer_id.to_bytes() {
            std::mem::swap(&mut a_config, &mut b_config);
        }
        let a_peer = a_config.peer_id;
        let b_peer = b_config.peer_id;
        let a_enrollment = PqPeerEnrollment {
            peer_id: a_peer,
            account_id: a_config.account_id,
            identity_key_hash: a_config.identity_key_hash,
        };
        let b_enrollment = PqPeerEnrollment {
            peer_id: b_peer,
            account_id: b_config.account_id,
            identity_key_hash: b_config.identity_key_hash,
        };
        let rotated_a_config = PqChannelLocalConfig {
            network_id: a_config.network_id,
            configuration_hash: [10; 32],
            epoch: a_config.epoch + 1,
            account_id: a_config.account_id,
            peer_id: a_config.peer_id,
            identity: a_config.identity.clone(),
            identity_key_hash: a_config.identity_key_hash,
            outbox_path: temp.path().join("a-new.outbox"),
            rooted_accounts: (0..=255).map(|id| AccountId([id; 32])).collect(),
        };
        let rotated_b_config = PqChannelLocalConfig {
            network_id: b_config.network_id,
            configuration_hash: [10; 32],
            epoch: b_config.epoch + 1,
            account_id: b_config.account_id,
            peer_id: b_config.peer_id,
            identity: b_config.identity.clone(),
            identity_key_hash: b_config.identity_key_hash,
            outbox_path: temp.path().join("b-new.outbox"),
            rooted_accounts: (0..=255).map(|id| AccountId([id; 32])).collect(),
        };

        let mut a = PqChannelSessionManager::new(a_config).unwrap();
        let mut b = PqChannelSessionManager::new(b_config).unwrap();
        a.enroll_peer(b_enrollment.clone()).unwrap();
        b.enroll_peer(a_enrollment.clone()).unwrap();
        let hello = a.start(b_peer).unwrap();
        let server = b.accept(a_peer, hello).unwrap();
        let finish = a.finish(b_peer, server).unwrap();
        b.complete(a_peer, finish).unwrap();
        a.confirm_application_ready(&b_peer).unwrap();
        let old_record = a
            .seal(
                &b_peer,
                PqChannelContentTypeV1::ConsensusVote,
                b"old-configuration vote",
            )
            .unwrap();

        // Model the swarm's atomic manager replacement. The long-term
        // identities remain enrolled, while all traffic keys and sequence
        // state are recreated under the new configuration/epoch scope.
        let mut rotated_a = PqChannelSessionManager::new(rotated_a_config).unwrap();
        let mut rotated_b = PqChannelSessionManager::new(rotated_b_config).unwrap();
        rotated_a.enroll_peer(b_enrollment).unwrap();
        rotated_b.enroll_peer(a_enrollment).unwrap();
        assert!(rotated_b.open(&a_peer, &old_record).is_err());

        let hello = rotated_a.start(b_peer).unwrap();
        let server = rotated_b.accept(a_peer, hello).unwrap();
        let finish = rotated_a.finish(b_peer, server).unwrap();
        rotated_b.complete(a_peer, finish).unwrap();
        rotated_a.confirm_application_ready(&b_peer).unwrap();
        assert!(rotated_b.open(&a_peer, &old_record).is_err());

        let new_record = rotated_a
            .seal(
                &b_peer,
                PqChannelContentTypeV1::ConsensusVote,
                b"new-configuration vote",
            )
            .unwrap();
        assert_eq!(
            rotated_b.open(&a_peer, &new_record).unwrap(),
            b"new-configuration vote"
        );
    }

    #[test]
    fn unknown_or_changed_enrollment_has_no_session_authority() {
        let temp = tempfile::tempdir().unwrap();
        let config = local_config(20, temp.path().join("unknown.outbox"));
        let unknown = Keypair::generate_ed25519().public().to_peer_id();
        let mut manager = PqChannelSessionManager::new(config).unwrap();
        assert!(manager.start(unknown).is_err());
        assert!(manager
            .seal(&unknown, PqChannelContentTypeV1::ConsensusVote, b"vote")
            .is_err());
    }

    #[test]
    fn bounded_quv_wire_shapes_fit_reserved_frame_budget() {
        let member = AccountId([40; 32]);
        let mut query = quv_query(1, member);
        query.candidate.authority_signature.clear();
        let base = query.candidate.encoded_size();
        // Extra byte accounts for the signature's larger SCALE length prefix.
        query.candidate.authority_signature = vec![0; 4096 - base - 1];
        assert_eq!(query.candidate.encoded_size(), 4096);
        let push = PqConsensusPayloadV1::QuvPushQuery(query.encode());
        let mut reply = quv_reply(1, member);
        reply.complete_snapshot = vec![query.candidate.clone(), query.candidate];
        // ML-DSA-44's fixed signature width. These are representation fixtures,
        // not signed/valid observations or authorizing transcripts.
        reply.signature = vec![0; 2420];
        let reply = PqConsensusPayloadV1::QuvReply(reply.encode());
        assert_eq!(push.encoded_size(), 4131);
        assert_eq!(reply.encoded_size(), 10915);
        for payload in [&push, &reply] {
            assert!(
                payload.encoded_size() as u64 <= ioi_types::app::QUV_OUTBOX_MAX_PAYLOAD_BYTES_V0
            );
        }
    }

    #[test]
    fn outbox_byte_budgets_preserve_quv_lanes_and_unrelated_recipients() {
        let temp = tempfile::tempdir().unwrap();
        let local = local_config(40, temp.path().join("bytes.outbox"));
        let recipient = AccountId([41; 32]);
        let mut store = PqDurableOutbox::open(&local).unwrap();
        let full = PqConsensusPayloadV1::Vote(vec![
            7;
            ioi_types::app::QUV_OUTBOX_NORMAL_BYTES_PER_RECIPIENT_V0
                as usize
                - 5
        ]);
        store.enqueue(recipient, full).unwrap();
        let before = std::fs::read(&local.outbox_path).unwrap();
        assert!(store
            .enqueue(recipient, PqConsensusPayloadV1::Vote(vec![8]))
            .unwrap_err()
            .to_string()
            .contains("byte budget"));
        assert!(!store.persistence_failed);
        assert_eq!(std::fs::read(&local.outbox_path).unwrap(), before);
        let push = PqConsensusPayloadV1::QuvPushQuery(
            codec::to_bytes_canonical(&quv_query(1, local.account_id)).unwrap(),
        );
        let reply = PqConsensusPayloadV1::QuvReply(
            codec::to_bytes_canonical(&quv_reply(2, local.account_id)).unwrap(),
        );
        store.enqueue(recipient, push).unwrap();
        store.enqueue(recipient, reply).unwrap();
        store
            .enqueue(AccountId([42; 32]), PqConsensusPayloadV1::Vote(vec![8]))
            .unwrap();
        let before = std::fs::read(&local.outbox_path).unwrap();
        let next_push = PqConsensusPayloadV1::QuvPushQuery(
            codec::to_bytes_canonical(&quv_query(3, local.account_id)).unwrap(),
        );
        assert!(store
            .enqueue(recipient, next_push.clone())
            .unwrap_err()
            .to_string()
            .contains("lane already occupied"));
        assert_eq!(std::fs::read(&local.outbox_path).unwrap(), before);
        store.retire_quv_pushes_for_operation([1; 32]).unwrap();
        store.enqueue(recipient, next_push).unwrap();
        let expected = store.state.clone();
        drop(store);
        let reopened = PqDurableOutbox::open(&local).unwrap();
        assert_eq!(reopened.state, expected);
        let mut invalid = reopened.state.clone();
        let extra = PqConsensusPayloadV1::Vote(vec![3]);
        let message_id = reopened.message_id(recipient, &extra).unwrap();
        invalid.entries.push(Arc::new(PqOutboxEntryV2 {
            recipient_account_id: recipient,
            message_id,
            payload: extra,
        }));
        drop(reopened);
        // Independently exercise defensive legacy recovery before conversion.
        persist_outbox(&local.outbox_path, &invalid).unwrap();
        let invalid_bytes = std::fs::read(&local.outbox_path).unwrap();
        assert!(PqDurableOutbox::open(&local)
            .err()
            .unwrap()
            .to_string()
            .contains("byte budget"));
        assert_eq!(std::fs::read(&local.outbox_path).unwrap(), invalid_bytes);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn normal_storage_capacity_refusal_preserves_live_quv_queue() {
        for (errno, quarantined, cleanup_blocked) in [
            (libc::ENOSPC, false, false),
            (libc::EDQUOT, false, false),
            (libc::EIO, true, false),
            (libc::ENOSPC, true, true),
        ] {
            for renamed in [false, true] {
                let temp = tempfile::tempdir().unwrap();
                let mut local = local_config(40, temp.path().join("capacity.outbox"));
                let recipient = AccountId([41; 32]);
                local.rooted_accounts = [local.account_id, recipient].into();
                let mut store = PqDurableOutbox::open(&local).unwrap();
                let quv_id = store
                    .enqueue(recipient, PqConsensusPayloadV1::QuvPushQuery(vec![7; 100]))
                    .unwrap();
                let normal_id = store
                    .enqueue(recipient, PqConsensusPayloadV1::Vote(vec![8; 100]))
                    .unwrap();
                let previous = store.state.clone();
                let index = std::fs::read(&local.outbox_path).unwrap();
                let payload = PqConsensusPayloadV1::Vote(vec![9; 100]);
                let pending_id = store.message_id(recipient, &payload).unwrap();
                let entry = Arc::new(PqOutboxEntryV2 {
                    recipient_account_id: recipient,
                    message_id: pending_id,
                    payload,
                });
                let mut next = previous.clone();
                next.entries.push(entry.clone());
                let target = outbox_index::entry_path(&local.outbox_path, &pending_id);
                let error = store
                    .commit_with(next, |_, _| {
                        outbox_index::new_normal_payload_with(
                            &target,
                            &entry.encode(),
                            |path, bytes| {
                                // Inject the filesystem error at the actual new-payload
                                // boundary, both before and after its unreferenced rename.
                                let staged = outbox_temp_path(path);
                                if cleanup_blocked {
                                    std::fs::create_dir(&staged)?;
                                } else {
                                    std::fs::write(&staged, bytes)?;
                                }
                                if renamed {
                                    std::fs::rename(&staged, path)?;
                                }
                                Err(std::io::Error::from_raw_os_error(errno).into())
                            },
                        )
                    })
                    .unwrap_err();
                assert_eq!(
                    error.is::<outbox_index::NormalCapacityRefusal>(),
                    !quarantined
                );
                assert_eq!(store.persistence_failed, quarantined);
                assert_eq!(store.state, previous);
                assert_eq!(std::fs::read(&local.outbox_path).unwrap(), index);
                if !quarantined {
                    assert!(!target.exists());
                    assert!(!outbox_temp_path(&target).exists());
                    assert_eq!(store.front(recipient).unwrap().0, quv_id);
                    store.acknowledge(recipient, quv_id).unwrap();
                    assert_eq!(store.front(recipient).unwrap().0, normal_id);
                    let reply = store
                        .enqueue(recipient, PqConsensusPayloadV1::QuvReply(vec![10; 100]))
                        .unwrap();
                    assert_eq!(store.front(recipient).unwrap().0, reply);
                } else {
                    assert!(store.front(recipient).is_none());
                    assert!(store.acknowledge(recipient, quv_id).is_err());
                }
                drop(store);
                if cleanup_blocked {
                    let obstruction = if renamed {
                        target.clone()
                    } else {
                        outbox_temp_path(&target)
                    };
                    assert!(obstruction.is_dir());
                    std::fs::remove_dir(obstruction).unwrap();
                }
                let recovered = PqDurableOutbox::open(&local).unwrap();
                assert_eq!(recovered.state.entries.len(), 2);
                assert!(!recovered
                    .state
                    .entries
                    .iter()
                    .any(|e| e.message_id == pending_id));
            }
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn quv_payload_arena_retains_both_lanes_across_atomic_replacement_and_restart() {
        use std::os::unix::fs::MetadataExt;
        let temp = tempfile::tempdir().unwrap();
        let mut local = local_config(40, temp.path().join("arena.outbox"));
        let recipient = AccountId([41; 32]);
        local.rooted_accounts = [local.account_id, recipient].into();
        let mut store = PqDurableOutbox::open(&local).unwrap();
        store
            .enqueue(
                recipient,
                PqConsensusPayloadV1::QuvPushQuery(vec![1; 16381]),
            )
            .unwrap();
        store
            .enqueue(recipient, PqConsensusPayloadV1::QuvReply(vec![2; 16381]))
            .unwrap();
        let arena_path = outbox_arena::path(&local.outbox_path);
        let arena_meta = std::fs::metadata(&arena_path).unwrap();
        for entry in &store.state.entries {
            assert_eq!(
                entry.payload.encoded_size() as u64,
                ioi_types::app::QUV_OUTBOX_MAX_PAYLOAD_BYTES_V0
            );
        }
        let previous = store.state.clone();
        let old_index = std::fs::read(&local.outbox_path).unwrap();
        let mut next = previous.clone();
        next.entries.clear();
        for payload in [
            PqConsensusPayloadV1::QuvPushQuery(vec![3; 16381]),
            PqConsensusPayloadV1::QuvReply(vec![4; 16381]),
        ] {
            next.entries.push(Arc::new(PqOutboxEntryV2 {
                recipient_account_id: recipient,
                message_id: store.message_id(recipient, &payload).unwrap(),
                payload,
            }));
        }
        assert!(store
            .commit_with(next.clone(), |path, next| {
                outbox_index::persist_with_hook(
                    path,
                    Some(&previous),
                    next,
                    Some(&local.rooted_accounts),
                    |phase| {
                        if phase == outbox_index::CommitPhase::PayloadsDurable {
                            Err(anyhow!("stop after arena sync"))
                        } else {
                            Ok(())
                        }
                    },
                )
            })
            .is_err());
        assert_eq!(std::fs::read(&local.outbox_path).unwrap(), old_index);
        assert!(store.persistence_failed);
        drop(store);
        let mut recovered = PqDurableOutbox::open(&local).unwrap();
        assert_eq!(recovered.state, previous);
        assert!(recovered
            .commit_with(next.clone(), |path, next| {
                outbox_index::persist_with_hook(
                    path,
                    Some(&previous),
                    next,
                    Some(&local.rooted_accounts),
                    |phase| {
                        if phase == outbox_index::CommitPhase::IndexExchanged {
                            Err(anyhow!("stop after exchange"))
                        } else {
                            Ok(())
                        }
                    },
                )
            })
            .is_err());
        drop(recovered);
        let recovered = PqDurableOutbox::open(&local).unwrap();
        assert_eq!(recovered.state, next);
        for entry in previous.entries.iter().chain(&next.entries) {
            assert!(!outbox_index::entry_path(&local.outbox_path, &entry.message_id).exists());
        }
        let file = File::open(&arena_path).unwrap();
        assert_eq!(file.metadata().unwrap().ino(), arena_meta.ino());
        assert_eq!(file.metadata().unwrap().len(), arena_meta.len());
        assert!(fs2::FileExt::allocated_size(&file).unwrap() >= arena_meta.len());
        let mut arena =
            outbox_arena::Arena::open(&local.outbox_path, &next, &local.rooted_accounts).unwrap();
        // Retired slot bytes are still present but did not re-enter the queue.
        for entry in &previous.entries {
            assert_eq!(arena.read(recipient, entry.message_id).unwrap(), **entry);
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn quv_payload_arena_refuses_corruption_without_retired_file_fallback() {
        let temp = tempfile::tempdir().unwrap();
        let mut local = local_config(40, temp.path().join("arena.outbox"));
        let recipient = AccountId([41; 32]);
        local.rooted_accounts = [local.account_id, recipient].into();
        let mut store = PqDurableOutbox::open(&local).unwrap();
        let id = store
            .enqueue(recipient, PqConsensusPayloadV1::QuvPushQuery(vec![7; 100]))
            .unwrap();
        let entry = store.state.entries[0].encode();
        let arena_path = outbox_arena::path(&local.outbox_path);
        let good = std::fs::read(&arena_path).unwrap();
        drop(store);
        let mut damaged = good.clone();
        let offset = damaged
            .windows(entry.len())
            .position(|v| v == entry)
            .unwrap();
        damaged[offset + 64] ^= 1;
        OpenOptions::new()
            .write(true)
            .open(&arena_path)
            .unwrap()
            .write_all(&damaged)
            .unwrap();
        let legacy_file = outbox_index::entry_path(&local.outbox_path, &id);
        std::fs::write(&legacy_file, &entry).unwrap();
        let index = std::fs::read(&local.outbox_path).unwrap();
        assert!(PqDurableOutbox::open(&local)
            .err()
            .unwrap()
            .to_string()
            .contains("checksum"));
        assert_eq!(std::fs::read(&arena_path).unwrap(), damaged);
        assert_eq!(std::fs::read(&local.outbox_path).unwrap(), index);
        assert!(legacy_file.exists());
        OpenOptions::new()
            .write(true)
            .open(&arena_path)
            .unwrap()
            .write_all(&good)
            .unwrap();
        let recovered = PqDurableOutbox::open(&local).unwrap();
        assert_eq!(recovered.state.entries[0].message_id, id);
        assert!(!legacy_file.exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn reserved_outbox_index_reuses_allocated_inodes_across_commits() {
        use std::os::unix::fs::MetadataExt;
        let temp = tempfile::tempdir().unwrap();
        let mut local = local_config(40, temp.path().join("reserved.outbox"));
        local.rooted_accounts = [AccountId([40; 32]), AccountId([41; 32])].into();
        let recipient = AccountId([41; 32]);
        let mut store = PqDurableOutbox::open(&local).unwrap();
        let spare = outbox_reservation::inactive(&local.outbox_path);
        let identity = |path: &Path| {
            let file = File::open(path).unwrap();
            let m = file.metadata().unwrap();
            assert!(fs2::FileExt::allocated_size(&file).unwrap() >= m.len());
            (m.dev(), m.ino(), m.len())
        };
        let first = identity(&local.outbox_path);
        let second = identity(&spare);
        assert_ne!(first.1, second.1);
        assert_eq!(first.2, second.2);
        for value in 0..8 {
            let id = store
                .enqueue(recipient, PqConsensusPayloadV1::Vote(vec![value; 100]))
                .unwrap();
            assert_eq!(identity(&local.outbox_path), second);
            assert_eq!(identity(&spare), first);
            store.acknowledge(recipient, id).unwrap();
            assert_eq!(identity(&local.outbox_path), first);
            assert_eq!(identity(&spare), second);
            assert!(!outbox_temp_path(&local.outbox_path).exists());
        }
        drop(store);
        assert!(PqDurableOutbox::open(&local)
            .unwrap()
            .state
            .entries
            .is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn reserved_outbox_index_refuses_lost_capacity_and_recovers_incomplete_spare() {
        let temp = tempfile::tempdir().unwrap();
        let mut local = local_config(40, temp.path().join("reserved.outbox"));
        local.rooted_accounts = [AccountId([40; 32]), AccountId([41; 32])].into();
        let recipient = AccountId([41; 32]);
        let mut store = PqDurableOutbox::open(&local).unwrap();
        let first = store
            .enqueue(recipient, PqConsensusPayloadV1::Vote(vec![1; 100]))
            .unwrap();
        let previous = store.state.clone();
        let active = std::fs::read(&local.outbox_path).unwrap();
        let mut next = previous.clone();
        next.entries.clear();
        assert!(store
            .commit_with(next, |path, next| {
                outbox_index::persist_with_hook(
                    path,
                    Some(&previous),
                    next,
                    Some(&local.rooted_accounts),
                    |phase| {
                        if phase == outbox_index::CommitPhase::InactiveIndexDurable {
                            Err(anyhow!("stop before exchange"))
                        } else {
                            Ok(())
                        }
                    },
                )
            })
            .is_err());
        assert!(store.persistence_failed);
        assert_eq!(std::fs::read(&local.outbox_path).unwrap(), active);
        drop(store);
        let spare = outbox_reservation::inactive(&local.outbox_path);
        // A torn inactive header is never a recovery authority.
        OpenOptions::new()
            .write(true)
            .open(&spare)
            .unwrap()
            .write_all(b"torn")
            .unwrap();
        let mut recovered = PqDurableOutbox::open(&local).unwrap();
        assert_eq!(recovered.state, previous);
        let active = std::fs::read(&local.outbox_path).unwrap();
        // Removed-preallocation control: a sparse file with the same length
        // must refuse before any index publication rather than silently refill.
        let length = std::fs::metadata(&spare).unwrap().len();
        let sparse = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&spare)
            .unwrap();
        sparse.set_len(length).unwrap();
        assert!(fs2::FileExt::allocated_size(&sparse).unwrap() < length);
        assert!(recovered.acknowledge(recipient, first).is_err());
        assert!(recovered.persistence_failed);
        assert_eq!(std::fs::read(&local.outbox_path).unwrap(), active);
        drop(recovered);
        let mut recovered = PqDurableOutbox::open(&local).unwrap();
        assert_eq!(recovered.state, previous);
        recovered.acknowledge(recipient, first).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn reserved_outbox_index_quarantines_exchange_before_directory_sync() {
        let temp = tempfile::tempdir().unwrap();
        let mut local = local_config(40, temp.path().join("reserved.outbox"));
        local.rooted_accounts = [AccountId([40; 32]), AccountId([41; 32])].into();
        let recipient = AccountId([41; 32]);
        let mut store = PqDurableOutbox::open(&local).unwrap();
        let first = store
            .enqueue(recipient, PqConsensusPayloadV1::Vote(vec![1; 100]))
            .unwrap();
        let previous = store.state.clone();
        let mut next = previous.clone();
        next.entries.clear();
        assert!(store
            .commit_with(next, |path, next| {
                outbox_index::persist_with_hook(
                    path,
                    Some(&previous),
                    next,
                    Some(&local.rooted_accounts),
                    |phase| {
                        if phase == outbox_index::CommitPhase::IndexExchanged {
                            Err(anyhow!("directory sync outcome unavailable"))
                        } else {
                            Ok(())
                        }
                    },
                )
            })
            .is_err());
        assert!(store.persistence_failed);
        assert_eq!(store.state, previous);
        assert!(store.front(recipient).is_none());
        assert!(store.acknowledge(recipient, first).is_err());
        assert!(outbox_index::entry_path(&local.outbox_path, &first).exists());
        drop(store);
        // Process reopen observes the exchanged index. Actual power loss may
        // preserve either pre-sync directory outcome; neither receives success.
        let recovered = PqDurableOutbox::open(&local).unwrap();
        assert!(recovered.state.entries.is_empty());
        assert!(!outbox_index::entry_path(&local.outbox_path, &first).exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn reserved_outbox_index_rejects_aliases_and_corrupt_active_image() {
        let temp = tempfile::tempdir().unwrap();
        let mut local = local_config(40, temp.path().join("reserved.outbox"));
        local.rooted_accounts = [AccountId([40; 32]), AccountId([41; 32])].into();
        let store = PqDurableOutbox::open(&local).unwrap();
        drop(store);
        let good = std::fs::read(&local.outbox_path).unwrap();
        let spare = outbox_reservation::inactive(&local.outbox_path);
        std::fs::remove_file(&spare).unwrap();
        std::fs::hard_link(&local.outbox_path, &spare).unwrap();
        assert!(PqDurableOutbox::open(&local).is_err());
        assert_eq!(std::fs::read(&local.outbox_path).unwrap(), good);
        std::fs::remove_file(&spare).unwrap();
        // Active checksum damage is refused without replacing the evidence.
        let mut bad = good.clone();
        bad[16] ^= 1;
        std::fs::write(&local.outbox_path, &bad).unwrap();
        assert!(PqDurableOutbox::open(&local).is_err());
        assert_eq!(std::fs::read(&local.outbox_path).unwrap(), bad);
        std::fs::write(&local.outbox_path, good).unwrap();
        assert!(PqDurableOutbox::open(&local).is_ok());
    }

    #[test]
    fn legacy_outbox_upgrade_recovers_interrupted_payload_staging() {
        let temp = tempfile::tempdir().unwrap();
        let local = local_config(40, temp.path().join("upgrade.outbox"));
        let mut store = PqDurableOutbox::open(&local).unwrap();
        store
            .enqueue(
                AccountId([41; 32]),
                PqConsensusPayloadV1::Vote(vec![8; 4096]),
            )
            .unwrap();
        let state = store.state.clone();
        drop(store);
        persist_outbox(&local.outbox_path, &state).unwrap();
        outbox_index::cleanup(&local.outbox_path, &state, false).unwrap();
        let legacy = std::fs::read(&local.outbox_path).unwrap();
        assert!(!outbox_index::is_index(&local.outbox_path).unwrap());
        assert!(
            outbox_index::persist_with_hook(&local.outbox_path, None, &state, None, |phase| {
                if phase == outbox_index::CommitPhase::PayloadsDurable {
                    Err(anyhow!("interrupted conversion"))
                } else {
                    Ok(())
                }
            })
            .is_err()
        );
        assert_eq!(std::fs::read(&local.outbox_path).unwrap(), legacy);
        let recovered = PqDurableOutbox::open(&local).unwrap();
        assert_eq!(recovered.state, state);
        assert!(recovered.indexed);
        assert!(outbox_index::is_index(&local.outbox_path).unwrap());
    }

    #[test]
    fn indexed_outbox_recovers_commit_boundaries_without_resurrecting_retirements() {
        use outbox_index::CommitPhase;
        let temp = tempfile::tempdir().unwrap();
        let local = local_config(40, temp.path().join("index.outbox"));
        let recipient = AccountId([41; 32]);
        let mut store = PqDurableOutbox::open(&local).unwrap();
        let first = store
            .enqueue(recipient, PqConsensusPayloadV1::Vote(vec![1; 4096]))
            .unwrap();
        let old_index = std::fs::read(&local.outbox_path).unwrap();
        let previous = store.state.clone();
        let payload = PqConsensusPayloadV1::Vote(vec![2; 4096]);
        let second = store.message_id(recipient, &payload).unwrap();
        let mut next = previous.clone();
        next.entries.push(Arc::new(PqOutboxEntryV2 {
            recipient_account_id: recipient,
            message_id: second,
            payload: payload.clone(),
        }));
        assert!(store
            .commit_with(next, |path, next| outbox_index::persist_with_hook(
                path,
                Some(&previous),
                next,
                Some(&local.rooted_accounts),
                |phase| if phase == CommitPhase::PayloadsDurable {
                    Err(anyhow!("interrupted before index"))
                } else {
                    Ok(())
                }
            ))
            .is_err());
        assert!(store.front(recipient).is_none());
        assert_eq!(std::fs::read(&local.outbox_path).unwrap(), old_index);
        assert!(outbox_index::entry_path(&local.outbox_path, &second).exists());
        drop(store);
        let mut recovered = PqDurableOutbox::open(&local).unwrap();
        assert_eq!(recovered.state.entries.len(), 1);
        assert!(!outbox_index::entry_path(&local.outbox_path, &second).exists());
        recovered.enqueue(recipient, payload).unwrap();
        let previous = recovered.state.clone();
        let mut next = previous.clone();
        next.entries.retain(|entry| entry.message_id != first);
        assert!(recovered
            .commit_with(next, |path, next| outbox_index::persist_with_hook(
                path,
                Some(&previous),
                next,
                Some(&local.rooted_accounts),
                |phase| if phase == CommitPhase::IndexDurable {
                    Err(anyhow!("interrupted before cleanup"))
                } else {
                    Ok(())
                }
            ))
            .is_err());
        assert!(outbox_index::entry_path(&local.outbox_path, &first).exists());
        drop(recovered);
        let recovered = PqDurableOutbox::open(&local).unwrap();
        assert_eq!(recovered.state.entries.len(), 1);
        assert_eq!(recovered.state.entries[0].message_id, second);
        assert!(!outbox_index::entry_path(&local.outbox_path, &first).exists());
    }

    #[cfg(unix)]
    #[test]
    fn indexed_outbox_preserves_unrelated_payload_files_and_refuses_corrupt_recovery() {
        use std::os::unix::fs::MetadataExt;
        let temp = tempfile::tempdir().unwrap();
        let local = local_config(40, temp.path().join("index.outbox"));
        let recipient = AccountId([41; 32]);
        let mut store = PqDurableOutbox::open(&local).unwrap();
        let first = store
            .enqueue(recipient, PqConsensusPayloadV1::Vote(vec![1; 4096]))
            .unwrap();
        let path = outbox_index::entry_path(&local.outbox_path, &first);
        let metadata = std::fs::metadata(&path).unwrap();
        let second = store
            .enqueue(recipient, PqConsensusPayloadV1::Vote(vec![2; 4096]))
            .unwrap();
        store.acknowledge(recipient, second).unwrap();
        let after = std::fs::metadata(&path).unwrap();
        assert_eq!(
            (after.ino(), after.mtime(), after.mtime_nsec()),
            (metadata.ino(), metadata.mtime(), metadata.mtime_nsec())
        );
        let valid = std::fs::read(&path).unwrap();
        let mut corrupted = valid.clone();
        *corrupted.last_mut().unwrap() ^= 1;
        std::fs::write(&path, &corrupted).unwrap();
        let orphan = outbox_index::entry_path(&local.outbox_path, &[99; 32]);
        std::fs::write(&orphan, b"orphan").unwrap();
        drop(store);
        assert!(PqDurableOutbox::open(&local).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), corrupted);
        assert!(orphan.exists(), "cleanup must follow complete validation");
        std::fs::write(&path, &valid).unwrap();
        let recovered = PqDurableOutbox::open(&local).unwrap();
        assert_eq!(recovered.state.entries.len(), 1);
        assert!(!orphan.exists());
    }

    #[test]
    fn rooted_outbox_scope_precedes_discovery_and_rejects_foreign_recovery() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("rooted.outbox");
        let mut local = local_config(40, path.clone());
        let remote = local_config(41, temp.path().join("remote.outbox"));
        local.rooted_accounts = [local.account_id, remote.account_id].into_iter().collect();
        let mut manager = PqChannelSessionManager::new(local.clone()).unwrap();
        let payload = PqConsensusPayloadV1::Vote(vec![1, 2, 3]);
        manager
            .enqueue_for_account(remote.account_id, payload.clone())
            .unwrap();
        assert!(manager.enrollments.is_empty());
        let bytes = std::fs::read(&path).unwrap();
        let foreign = local_config(42, temp.path().join("foreign.outbox"));
        assert!(manager
            .enqueue_for_account(foreign.account_id, payload)
            .is_err());
        assert!(manager
            .enroll_peer(PqPeerEnrollment {
                peer_id: foreign.peer_id,
                account_id: foreign.account_id,
                identity_key_hash: foreign.identity_key_hash
            })
            .is_err());
        assert!(manager.enrollments.is_empty());
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
        drop(manager);
        let mut narrower = local.clone();
        narrower.rooted_accounts.remove(&remote.account_id);
        assert!(PqChannelSessionManager::new(narrower).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
        let reopened = PqChannelSessionManager::new(local).unwrap();
        assert_eq!(reopened.outbox.state.entries.len(), 1);
    }

    #[test]
    fn outbox_streaming_recovery_refuses_truncation_and_trailing_bytes() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("strict.outbox");
        let local = local_config(40, path.clone());
        let mut outbox = PqDurableOutbox::open(&local).unwrap();
        outbox
            .enqueue(
                AccountId([41; 32]),
                PqConsensusPayloadV1::Vote(vec![9; 70000]),
            )
            .unwrap();
        drop(outbox);
        let good = std::fs::read(&path).unwrap();
        for end in [0, 4, 112, good.len() - 1] {
            std::fs::write(&path, &good[..end]).unwrap();
            assert!(PqDurableOutbox::open(&local).is_err());
            assert_eq!(std::fs::read(&path).unwrap(), good[..end]);
        }
        let mut trailing = good.clone();
        trailing.push(0);
        std::fs::write(&path, &trailing).unwrap();
        assert!(PqDurableOutbox::open(&local).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), trailing);
        std::fs::write(&path, &good).unwrap();
        let reopened = PqDurableOutbox::open(&local).unwrap();
        assert_eq!(reopened.state.entries.len(), 1);
        assert_eq!(std::fs::read(&path).unwrap(), good);
    }

    #[test]
    fn outbox_streaming_preserves_v2_bytes_and_returns_write_errors() {
        let temp = tempfile::tempdir().unwrap();
        let local = local_config(40, temp.path().join("stream.outbox"));
        let mut outbox = PqDurableOutbox::open(&local).unwrap();
        outbox
            .enqueue(
                AccountId([41; 32]),
                PqConsensusPayloadV1::Vote(vec![9; 70_000]),
            )
            .unwrap();
        let state = &outbox.state;
        let old_entries: Vec<PqOutboxEntryV2> = state
            .entries
            .iter()
            .map(|entry| entry.as_ref().clone())
            .collect();
        let old_bytes = (
            state.protocol_version,
            state.schema_version,
            state.network_id,
            state.configuration_hash,
            state.epoch,
            state.local_account_id,
            old_entries,
        )
            .encode();
        let mut streamed = Vec::new();
        encode_outbox_to(state, &mut streamed).unwrap();
        assert_eq!(streamed, old_bytes);
        let legacy_path = temp.path().join("legacy-v2.outbox");
        persist_outbox(&legacy_path, state).unwrap();
        assert_eq!(std::fs::read(&legacy_path).unwrap(), old_bytes);
        let staged = state.clone();
        assert!(Arc::ptr_eq(&staged.entries[0], &state.entries[0]));
        struct FailAfterPrefix {
            calls: usize,
        }
        impl Write for FailAfterPrefix {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.calls += 1;
                if self.calls >= 2 {
                    return Err(std::io::Error::other("retained write failure"));
                }
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let mut failing = FailAfterPrefix { calls: 0 };
        let error = encode_outbox_to(state, &mut failing).unwrap_err();
        assert_eq!(error.to_string(), "retained write failure");
        assert_eq!(failing.calls, 2);
        assert_eq!(std::fs::read(&legacy_path).unwrap(), old_bytes);
    }

    #[test]
    fn durable_outbox_enforces_record_plaintext_boundary_before_mutation() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("bounded.outbox");
        let local = local_config(40, path.clone());
        let recipient = AccountId([41; 32]);
        let mut outbox = PqDurableOutbox::open(&local).unwrap();
        // One enum byte and four SCALE compact-length bytes at this size.
        let payload = PqConsensusPayloadV1::Vote(vec![7; PQ_CHANNEL_MAX_RECORD_PLAINTEXT_V1 - 5]);
        assert_eq!(payload.encoded_size(), PQ_CHANNEL_MAX_RECORD_PLAINTEXT_V1);
        outbox.enqueue(recipient, payload).unwrap();
        let retained = std::fs::read(&path).unwrap();
        let oversized = PqConsensusPayloadV1::Vote(vec![7; PQ_CHANNEL_MAX_RECORD_PLAINTEXT_V1 - 4]);
        assert_eq!(
            oversized.encoded_size(),
            PQ_CHANNEL_MAX_RECORD_PLAINTEXT_V1 + 1
        );
        let error = outbox.enqueue(recipient, oversized).unwrap_err();
        assert!(error.to_string().contains("record plaintext limit"));
        assert_eq!(std::fs::read(&path).unwrap(), retained);
        assert_eq!(outbox.state.entries.len(), 1);
        assert!(!outbox_temp_path(&path).exists());
        drop(outbox);
        let reopened = PqDurableOutbox::open(&local).unwrap();
        assert_eq!(reopened.state.entries.len(), 1);
        assert_eq!(
            reopened.state.entries[0].payload.encoded_size(),
            PQ_CHANNEL_MAX_RECORD_PLAINTEXT_V1
        );
        let mut invalid = reopened.state.clone();
        drop(reopened);
        Arc::make_mut(&mut invalid.entries[0]).payload =
            PqConsensusPayloadV1::Vote(vec![7; PQ_CHANNEL_MAX_RECORD_PLAINTEXT_V1 - 4]);
        // Fixture bypasses admission to exercise defensive recovery independently.
        persist_outbox(&path, &invalid).unwrap();
        let invalid_bytes = std::fs::read(&path).unwrap();
        let error = PqDurableOutbox::open(&local).err().unwrap();
        assert!(error.to_string().contains("record plaintext limit"));
        assert_eq!(std::fs::read(&path).unwrap(), invalid_bytes);
    }

    #[test]
    fn durable_outbox_survives_restart_and_deletes_only_after_ack() {
        let temp = tempfile::tempdir().unwrap();
        let outbox_path = temp.path().join("durable.outbox");
        let config = local_config(40, outbox_path.clone());
        let reopened_config = PqChannelLocalConfig {
            network_id: config.network_id,
            configuration_hash: config.configuration_hash,
            epoch: config.epoch,
            account_id: config.account_id,
            peer_id: config.peer_id,
            identity: config.identity.clone(),
            identity_key_hash: config.identity_key_hash,
            outbox_path: outbox_path.clone(),
            rooted_accounts: (0..=255).map(|id| AccountId([id; 32])).collect(),
        };
        let remote = local_config(41, temp.path().join("remote.outbox"));
        let enrollment = PqPeerEnrollment {
            peer_id: remote.peer_id,
            account_id: remote.account_id,
            identity_key_hash: remote.identity_key_hash,
        };
        let payload = PqConsensusPayloadV1::Vote(b"durable vote".to_vec());

        let mut first = PqChannelSessionManager::new(config).unwrap();
        first.enroll_peer(enrollment.clone()).unwrap();
        let message_id = first.enqueue(remote.peer_id, payload.clone()).unwrap();
        assert_eq!(
            first.pending_front(&remote.peer_id),
            Some((message_id, payload.clone()))
        );
        // A clone cannot race the journal owner and manufacture a second
        // delivery/ack history.
        assert!(PqChannelSessionManager::new(PqChannelLocalConfig {
            network_id: reopened_config.network_id,
            configuration_hash: reopened_config.configuration_hash,
            epoch: reopened_config.epoch,
            account_id: reopened_config.account_id,
            peer_id: reopened_config.peer_id,
            identity: reopened_config.identity.clone(),
            identity_key_hash: reopened_config.identity_key_hash,
            outbox_path: outbox_path.clone(),
            rooted_accounts: (0..=255).map(|id| AccountId([id; 32])).collect(),
        })
        .is_err());
        drop(first);

        let final_config = PqChannelLocalConfig {
            network_id: reopened_config.network_id,
            configuration_hash: reopened_config.configuration_hash,
            epoch: reopened_config.epoch,
            account_id: reopened_config.account_id,
            peer_id: reopened_config.peer_id,
            identity: reopened_config.identity.clone(),
            identity_key_hash: reopened_config.identity_key_hash,
            outbox_path: outbox_path.clone(),
            rooted_accounts: (0..=255).map(|id| AccountId([id; 32])).collect(),
        };
        let mut reopened = PqChannelSessionManager::new(reopened_config).unwrap();
        reopened.enroll_peer(enrollment.clone()).unwrap();
        assert_eq!(
            reopened.pending_front(&remote.peer_id),
            Some((message_id, payload))
        );
        reopened.acknowledge(&remote.peer_id, message_id).unwrap();
        assert!(reopened.pending_front(&remote.peer_id).is_none());
        drop(reopened);

        let mut final_open = PqChannelSessionManager::new(final_config).unwrap();
        final_open.enroll_peer(enrollment).unwrap();
        assert!(final_open.pending_front(&remote.peer_id).is_none());
    }

    #[test]
    fn terminal_async_retirement_is_instance_scoped_and_durable() {
        let temp = tempfile::tempdir().unwrap();
        let outbox_path = temp.path().join("retired-async.outbox");
        let config = local_config(60, outbox_path.clone());
        let reopened_config = config.clone();
        let remote = local_config(61, temp.path().join("remote-retired-async.outbox"));
        let enrollment = PqPeerEnrollment {
            peer_id: remote.peer_id,
            account_id: remote.account_id,
            identity_key_hash: remote.identity_key_hash,
        };
        let async_payload = |instance_hash: [u8; 32]| {
            let payload = vec![instance_hash[0]];
            let carrier = AftAsyncCarrierV1 {
                protocol_version: AFT_ASYNC_PROTOCOL_VERSION_V1,
                schema_version: AFT_ASYNC_SCHEMA_VERSION_V1,
                instance_hash,
                body: AftAsyncCarrierBodyV1::ProposalPayload {
                    descriptor: AftAsyncProposalDescriptorV1 {
                        instance_hash,
                        proposer: 0,
                        proposal_hash: aft_async_proposal_payload_hash(&payload).unwrap(),
                        payload_len: payload.len() as u64,
                        parent_root: [9; 32],
                    },
                    payload,
                },
            };
            PqConsensusPayloadV1::AftAsyncOrdering(codec::to_bytes_canonical(&carrier).unwrap())
        };

        let mut manager = PqChannelSessionManager::new(config).unwrap();
        manager.enroll_peer(enrollment.clone()).unwrap();
        let retired_id = manager
            .enqueue(remote.peer_id, async_payload([7; 32]))
            .unwrap();
        manager
            .enqueue(remote.peer_id, async_payload([8; 32]))
            .unwrap();
        manager
            .enqueue(
                remote.peer_id,
                PqConsensusPayloadV1::AftTimeoutVote(vec![3]),
            )
            .unwrap();

        let retired = manager.retire_aft_async_instance([7; 32]).unwrap();
        assert_eq!(retired, std::collections::BTreeSet::from([retired_id]));
        assert_eq!(manager.outbox.state.entries.len(), 2);
        assert!(manager.outbox.state.entries.iter().all(|entry| {
            !matches!(
                &entry.payload,
                PqConsensusPayloadV1::AftAsyncOrdering(bytes)
                    if codec::from_bytes_canonical::<AftAsyncCarrierV1>(bytes)
                        .is_ok_and(|carrier| carrier.instance_hash == [7; 32])
            )
        }));
        drop(manager);

        let reopened = PqChannelSessionManager::new(reopened_config).unwrap();
        assert_eq!(reopened.outbox.state.entries.len(), 2);
    }

    #[test]
    fn quv_uses_reserved_priority_ahead_of_normal_consensus_outbox() {
        let temp = tempfile::tempdir().unwrap();
        let config = local_config(62, temp.path().join("quv-priority.outbox"));
        let remote = local_config(63, temp.path().join("remote-quv-priority.outbox"));
        let enrollment = PqPeerEnrollment {
            peer_id: remote.peer_id,
            account_id: remote.account_id,
            identity_key_hash: remote.identity_key_hash,
        };
        let normal = PqConsensusPayloadV1::Vote(b"older normal vote".to_vec());
        let quv = PqConsensusPayloadV1::QuvPushQuery(b"deadline-bound query".to_vec());

        let mut manager = PqChannelSessionManager::new(config).unwrap();
        manager.enroll_peer(enrollment).unwrap();
        let normal_id = manager.enqueue(remote.peer_id, normal.clone()).unwrap();
        let quv_id = manager.enqueue(remote.peer_id, quv.clone()).unwrap();
        assert_eq!(manager.pending_front(&remote.peer_id), Some((quv_id, quv)));
        manager.acknowledge(&remote.peer_id, quv_id).unwrap();
        assert_eq!(
            manager.pending_front(&remote.peer_id),
            Some((normal_id, normal))
        );
    }

    #[test]
    fn outbox_persistence_error_requires_reopen_before_retry_or_drain() {
        for published in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let config = local_config(68, temp.path().join("uncertain.outbox"));
            let recipient = AccountId([69; 32]);
            let query = quv_query(23, config.account_id);
            let payload =
                PqConsensusPayloadV1::QuvPushQuery(codec::to_bytes_canonical(&query).unwrap());
            let mut outbox = PqDurableOutbox::open(&config).unwrap();
            let message_id = outbox.enqueue(recipient, payload.clone()).unwrap();
            let mut next = outbox.state.clone();
            next.entries.clear();
            if published {
                // Model an error reported after publication. The real writer
                // performs the replacement; only the reported result is injected.
                let previous = outbox.state.clone();
                assert!(outbox
                    .commit_with(next, |path, state| {
                        outbox_index::persist(
                            path,
                            Some(&previous),
                            state,
                            Some(&config.rooted_accounts),
                        )?;
                        Err(anyhow!("injected post-publication synchronization error"))
                    })
                    .is_err());
            } else {
                // Exercise an actual inactive-index open error before exchange.
                let inactive = outbox_reservation::inactive(&config.outbox_path);
                std::fs::remove_file(&inactive).unwrap();
                std::fs::create_dir(&inactive).unwrap();
                assert!(outbox
                    .retire_quv_pushes_for_operation(query.verifier_nonce)
                    .is_err());
                std::fs::remove_dir(&inactive).unwrap();
            }
            let disk_after_error = std::fs::read(&config.outbox_path).unwrap();
            assert!(outbox.persistence_failed);
            assert!(outbox.front(recipient).is_none());
            assert!(outbox.recipients().is_empty());
            // Even duplicate enqueue and empty retirement must not report
            // success from the stale in-memory snapshot after the fault clears.
            assert!(outbox.enqueue(recipient, payload.clone()).is_err());
            assert!(outbox.acknowledge(recipient, message_id).is_err());
            assert!(outbox
                .retire_quv_pushes_for_operation(query.verifier_nonce)
                .is_err());
            assert!(outbox.retire_quv_replies_for_recipient(recipient).is_err());
            assert_eq!(
                std::fs::read(&config.outbox_path).unwrap(),
                disk_after_error
            );
            drop(outbox);

            let mut reopened = PqDurableOutbox::open(&config).unwrap();
            assert!(!reopened.persistence_failed);
            assert_eq!(reopened.front(recipient).is_some(), !published);
            reopened.enqueue(recipient, payload.clone()).unwrap();
            assert_eq!(reopened.front(recipient), Some((message_id, payload)));
            reopened.acknowledge(recipient, message_id).unwrap();
            drop(reopened);
            assert!(PqDurableOutbox::open(&config)
                .unwrap()
                .front(recipient)
                .is_none());
        }
    }

    #[test]
    fn completed_quv_operation_retires_unacknowledged_requests_durably() {
        let temp = tempfile::tempdir().unwrap();
        let config = local_config(64, temp.path().join("quv-retirement.outbox"));
        let reopened_config = config.clone();
        let remote = local_config(65, temp.path().join("remote-quv-retirement.outbox"));
        let enrollment = PqPeerEnrollment {
            peer_id: remote.peer_id,
            account_id: remote.account_id,
            identity_key_hash: remote.identity_key_hash,
        };
        let query = quv_query(17, config.account_id);
        let query_payload =
            PqConsensusPayloadV1::QuvPushQuery(codec::to_bytes_canonical(&query).unwrap());
        let normal = PqConsensusPayloadV1::Vote(b"must survive QUV retirement".to_vec());

        let mut manager = PqChannelSessionManager::new(config).unwrap();
        manager.enroll_peer(enrollment.clone()).unwrap();
        let query_id = manager.enqueue(remote.peer_id, query_payload).unwrap();
        let normal_id = manager.enqueue(remote.peer_id, normal.clone()).unwrap();
        let retired = manager.retire_quv_operation(query.verifier_nonce).unwrap();
        assert_eq!(retired, std::collections::BTreeSet::from([query_id]));
        assert_eq!(
            manager.pending_front(&remote.peer_id),
            Some((normal_id, normal.clone()))
        );
        drop(manager);

        let mut reopened = PqChannelSessionManager::new(reopened_config).unwrap();
        reopened.enroll_peer(enrollment).unwrap();
        assert_eq!(
            reopened.pending_front(&remote.peer_id),
            Some((normal_id, normal))
        );
    }

    #[test]
    fn newer_quv_reply_atomically_replaces_ack_withheld_reply() {
        let temp = tempfile::tempdir().unwrap();
        let config = local_config(66, temp.path().join("quv-reply-replace.outbox"));
        let reopened_config = config.clone();
        let remote = local_config(67, temp.path().join("remote-quv-reply-replace.outbox"));
        let enrollment = PqPeerEnrollment {
            peer_id: remote.peer_id,
            account_id: remote.account_id,
            identity_key_hash: remote.identity_key_hash,
        };
        let first = PqConsensusPayloadV1::QuvReply(
            codec::to_bytes_canonical(&quv_reply(20, config.account_id)).unwrap(),
        );
        let second = PqConsensusPayloadV1::QuvReply(
            codec::to_bytes_canonical(&quv_reply(21, config.account_id)).unwrap(),
        );

        let mut manager = PqChannelSessionManager::new(config).unwrap();
        manager.enroll_peer(enrollment.clone()).unwrap();
        let (first_id, initially_retired) = manager
            .enqueue_quv_reply_for_account(remote.account_id, first)
            .unwrap();
        assert!(initially_retired.is_empty());
        let (second_id, retired) = manager
            .enqueue_quv_reply_for_account(remote.account_id, second.clone())
            .unwrap();
        assert_eq!(retired, std::collections::BTreeSet::from([first_id]));
        assert_eq!(
            manager.pending_front(&remote.peer_id),
            Some((second_id, second.clone()))
        );
        drop(manager);

        let mut reopened = PqChannelSessionManager::new(reopened_config).unwrap();
        reopened.enroll_peer(enrollment).unwrap();
        assert_eq!(
            reopened.pending_front(&remote.peer_id),
            Some((second_id, second))
        );
    }

    #[test]
    fn account_addressed_outbox_survives_restart_before_peer_discovery() {
        let temp = tempfile::tempdir().unwrap();
        let outbox_path = temp.path().join("pre-enrollment.outbox");
        let config = local_config(42, outbox_path.clone());
        let reopened_config = config.clone();
        let remote = local_config(43, temp.path().join("remote-pre-enrollment.outbox"));
        let enrollment = PqPeerEnrollment {
            peer_id: remote.peer_id,
            account_id: remote.account_id,
            identity_key_hash: remote.identity_key_hash,
        };
        let payload = PqConsensusPayloadV1::AftAsyncOrdering(b"private ASKS share".to_vec());

        let mut first = PqChannelSessionManager::new(config).unwrap();
        let message_id = first
            .enqueue_for_account(remote.account_id, payload.clone())
            .unwrap();
        assert!(first.pending_peers().is_empty());
        drop(first);

        let local_enrollment = PqPeerEnrollment {
            peer_id: reopened_config.peer_id,
            account_id: reopened_config.account_id,
            identity_key_hash: reopened_config.identity_key_hash,
        };
        let local_peer = reopened_config.peer_id;
        let mut reopened = PqChannelSessionManager::new(reopened_config).unwrap();
        assert!(reopened.pending_peers().is_empty());
        reopened.enroll_peer(enrollment).unwrap();
        assert!(reopened.pending_peers().is_empty());
        assert_eq!(reopened.peer_for_account(remote.account_id), None);
        let mut remote_manager = PqChannelSessionManager::new(remote.clone()).unwrap();
        remote_manager.enroll_peer(local_enrollment).unwrap();
        if reopened.should_initiate(&remote.peer_id) {
            let hello = reopened.start(remote.peer_id).unwrap();
            let server = remote_manager.accept(local_peer, hello).unwrap();
            let finish = reopened.finish(remote.peer_id, server).unwrap();
            remote_manager.complete(local_peer, finish).unwrap();
            reopened.confirm_application_ready(&remote.peer_id).unwrap();
        } else {
            let hello = remote_manager.start(local_peer).unwrap();
            let server = reopened.accept(remote.peer_id, hello).unwrap();
            let finish = remote_manager.finish(local_peer, server).unwrap();
            reopened.complete(remote.peer_id, finish).unwrap();
            remote_manager
                .confirm_application_ready(&local_peer)
                .unwrap();
        }
        assert_eq!(reopened.pending_peers(), vec![remote.peer_id]);
        assert_eq!(
            reopened.pending_front(&remote.peer_id),
            Some((message_id, payload))
        );
    }

    #[test]
    fn provisional_enrollment_capacity_is_bounded_per_account() {
        let temp = tempfile::tempdir().unwrap();
        let config = local_config(44, temp.path().join("bounded.outbox"));
        let remote = local_config(45, temp.path().join("remote.outbox"));
        let mut manager = PqChannelSessionManager::new(config).unwrap();
        for _ in 0..PQ_PROVISIONAL_PER_ACCOUNT_MAX {
            manager
                .enroll_peer(PqPeerEnrollment {
                    peer_id: Keypair::generate_ed25519().public().to_peer_id(),
                    account_id: remote.account_id,
                    identity_key_hash: remote.identity_key_hash,
                })
                .unwrap();
        }
        let refused = manager
            .enroll_peer(PqPeerEnrollment {
                peer_id: remote.peer_id,
                account_id: remote.account_id,
                identity_key_hash: remote.identity_key_hash,
            })
            .unwrap_err();
        assert_eq!(
            refused.to_string(),
            "PQ provisional enrollment capacity exceeded"
        );
        assert_eq!(
            manager.provisional_enrollments.len(),
            PQ_PROVISIONAL_PER_ACCOUNT_MAX
        );
        assert_eq!(manager.peer_for_account(remote.account_id), None);
        manager
            .enroll_peer(PqPeerEnrollment {
                peer_id: Keypair::generate_ed25519().public().to_peer_id(),
                account_id: AccountId([99; 32]),
                identity_key_hash: [98; 32],
            })
            .unwrap();
        assert_eq!(
            manager.provisional_enrollments.len(),
            PQ_PROVISIONAL_PER_ACCOUNT_MAX + 1
        );
    }

    #[test]
    fn provisional_enrollment_global_capacity_is_bounded() {
        let temp = tempfile::tempdir().unwrap();
        let mut config = local_config(48, temp.path().join("global-bound.outbox"));
        // This generic-PQ capacity fixture declares its synthetic rooted
        // accounts independently of the subsequent provisional carriers.
        for index in 0..PQ_PROVISIONAL_ENROLLMENTS_MAX {
            let mut account = [0; 32];
            account[..8].copy_from_slice(&(index as u64 + 100).to_le_bytes());
            config.rooted_accounts.insert(AccountId(account));
        }
        let mut manager = PqChannelSessionManager::new(config).unwrap();
        // Isolate the capacity test from wall-clock expiry on loaded hosts.
        // The separate expiry test exercises real admission timestamps.
        let retained_until = Instant::now() + Duration::from_secs(3_600);
        for index in 0..PQ_PROVISIONAL_ENROLLMENTS_MAX {
            let peer = Keypair::generate_ed25519().public().to_peer_id();
            let mut account = [0; 32];
            account[..8].copy_from_slice(&(index as u64 + 100).to_le_bytes());
            manager
                .enroll_peer(PqPeerEnrollment {
                    peer_id: peer,
                    account_id: AccountId(account),
                    identity_key_hash: [98; 32],
                })
                .unwrap();
            manager.provisional_enrollments.insert(peer, retained_until);
        }
        let error = manager
            .enroll_peer(PqPeerEnrollment {
                peer_id: Keypair::generate_ed25519().public().to_peer_id(),
                account_id: AccountId([99; 32]),
                identity_key_hash: [98; 32],
            })
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "PQ provisional enrollment capacity exceeded"
        );
        assert_eq!(
            manager.provisional_enrollments.len(),
            PQ_PROVISIONAL_ENROLLMENTS_MAX
        );
        assert_eq!(manager.enrollments.len(), PQ_PROVISIONAL_ENROLLMENTS_MAX);
        assert!(manager.sessions.is_empty());
        assert!(manager.authenticated_enrollments.is_empty());
    }

    #[test]
    fn provisional_expiry_removes_pending_keys_without_refresh_extension() {
        let temp = tempfile::tempdir().unwrap();
        let mut local = local_config(46, temp.path().join("local-expiry.outbox"));
        let mut remote = local_config(47, temp.path().join("remote-expiry.outbox"));
        if local.peer_id.to_bytes() > remote.peer_id.to_bytes() {
            std::mem::swap(&mut local, &mut remote);
        }
        let enrollment = PqPeerEnrollment {
            peer_id: remote.peer_id,
            account_id: remote.account_id,
            identity_key_hash: remote.identity_key_hash,
        };
        let peer = enrollment.peer_id;
        let mut manager = PqChannelSessionManager::new(local).unwrap();
        manager.enroll_peer(enrollment.clone()).unwrap();
        let original_time = manager.provisional_enrollments[&peer];
        manager.start(peer).unwrap();
        manager.enroll_peer(enrollment.clone()).unwrap();
        assert_eq!(manager.provisional_enrollments[&peer], original_time);
        assert!(manager.pending_initiators.contains_key(&peer));
        manager
            .provisional_enrollments
            .insert(peer, Instant::now() - PQ_PROVISIONAL_ENROLLMENT_LIFETIME);
        assert_eq!(
            manager.enrollment(&peer).unwrap_err().to_string(),
            "PQ provisional enrollment expired"
        );
        manager.expire_provisional_enrollments();
        assert!(!manager.enrollments.contains_key(&peer));
        assert!(!manager.provisional_enrollments.contains_key(&peer));
        assert!(!manager.pending_initiators.contains_key(&peer));
        assert!(!manager.peer_capabilities.contains_key(&peer));
        assert!(!manager.is_established(&peer));
        manager.enroll_peer(enrollment).unwrap();
        manager.start(peer).unwrap();
        assert!(manager.pending_initiators.contains_key(&peer));
    }

    #[test]
    fn unproven_carrier_cannot_squat_a_rooted_account() {
        let temp = tempfile::tempdir().unwrap();
        let mut local = local_config(44, temp.path().join("local.outbox"));
        let mut remote = local_config(45, temp.path().join("remote.outbox"));
        if local.peer_id.to_bytes() > remote.peer_id.to_bytes() {
            std::mem::swap(&mut local, &mut remote);
        }
        let genuine_peer = remote.peer_id;
        let squatter_peer = Keypair::generate_ed25519().public().to_peer_id();
        let mut manager = PqChannelSessionManager::new(local.clone()).unwrap();
        manager
            .enroll_peer(PqPeerEnrollment {
                peer_id: squatter_peer,
                account_id: remote.account_id,
                identity_key_hash: remote.identity_key_hash,
            })
            .unwrap();
        manager
            .enroll_peer(PqPeerEnrollment {
                peer_id: genuine_peer,
                account_id: remote.account_id,
                identity_key_hash: remote.identity_key_hash,
            })
            .unwrap();
        assert_eq!(manager.peer_for_account(remote.account_id), None);

        let mut genuine = PqChannelSessionManager::new(remote.clone()).unwrap();
        genuine
            .enroll_peer(PqPeerEnrollment {
                peer_id: local.peer_id,
                account_id: local.account_id,
                identity_key_hash: local.identity_key_hash,
            })
            .unwrap();
        let hello = manager.start(genuine_peer).unwrap();
        let server = genuine.accept(local.peer_id, hello).unwrap();
        let finish = manager.finish(genuine_peer, server).unwrap();
        genuine.complete(local.peer_id, finish).unwrap();
        manager.confirm_application_ready(&genuine_peer).unwrap();
        assert!(manager.provisional_enrollments.is_empty());
        assert!(!manager.enrollments.contains_key(&squatter_peer));
        manager.expire_provisional_enrollments();
        assert!(manager.is_application_ready(&genuine_peer));
        let change_error = manager
            .enroll_peer(PqPeerEnrollment {
                peer_id: genuine_peer,
                account_id: remote.account_id,
                identity_key_hash: [99; 32],
            })
            .unwrap_err();
        assert_eq!(
            change_error.to_string(),
            "PQ authenticated enrollment change requires reconfiguration"
        );
        assert!(manager.is_application_ready(&genuine_peer));
        assert_eq!(
            manager.peer_for_account(remote.account_id),
            Some(genuine_peer)
        );
        assert!(manager
            .enroll_peer(PqPeerEnrollment {
                peer_id: Keypair::generate_ed25519().public().to_peer_id(),
                account_id: remote.account_id,
                identity_key_hash: remote.identity_key_hash,
            })
            .is_err());
    }

    #[test]
    fn durable_outbox_refuses_cross_configuration_reuse() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("scoped.outbox");
        let config = local_config(50, path.clone());
        let mut changed = PqChannelLocalConfig {
            network_id: config.network_id,
            configuration_hash: config.configuration_hash,
            epoch: config.epoch,
            account_id: config.account_id,
            peer_id: config.peer_id,
            identity: config.identity.clone(),
            identity_key_hash: config.identity_key_hash,
            outbox_path: path,
            rooted_accounts: (0..=255).map(|id| AccountId([id; 32])).collect(),
        };
        PqChannelSessionManager::new(config).unwrap();
        changed.configuration_hash[0] ^= 1;
        assert!(PqChannelSessionManager::new(changed).is_err());
    }

    #[test]
    fn unacknowledged_payload_reseals_under_a_fresh_session_after_restart() {
        let temp = tempfile::tempdir().unwrap();
        let mut a_config = local_config(60, temp.path().join("a-restart.outbox"));
        let mut b_config = local_config(61, temp.path().join("b-restart.outbox"));
        if a_config.peer_id.to_bytes() > b_config.peer_id.to_bytes() {
            std::mem::swap(&mut a_config, &mut b_config);
        }
        let a_peer = a_config.peer_id;
        let b_peer = b_config.peer_id;
        let a_enrollment = PqPeerEnrollment {
            peer_id: a_peer,
            account_id: a_config.account_id,
            identity_key_hash: a_config.identity_key_hash,
        };
        let b_enrollment = PqPeerEnrollment {
            peer_id: b_peer,
            account_id: b_config.account_id,
            identity_key_hash: b_config.identity_key_hash,
        };

        let mut a = PqChannelSessionManager::new(a_config.clone()).unwrap();
        let mut b = PqChannelSessionManager::new(b_config.clone()).unwrap();
        a.enroll_peer(b_enrollment.clone()).unwrap();
        b.enroll_peer(a_enrollment.clone()).unwrap();
        let hello = a.start(b_peer).unwrap();
        let server = b.accept(a_peer, hello).unwrap();
        let finish = a.finish(b_peer, server).unwrap();
        b.complete(a_peer, finish).unwrap();
        a.confirm_application_ready(&b_peer).unwrap();
        let payload = PqConsensusPayloadV1::Vote(b"retry after crash".to_vec());
        a.enqueue(b_peer, payload.clone()).unwrap();
        let plaintext = codec::to_bytes_canonical(&payload).unwrap();
        let before_crash = a
            .seal(&b_peer, PqChannelContentTypeV1::ConsensusVote, &plaintext)
            .unwrap();
        assert_eq!(before_crash.sequence, 0);
        drop(a);
        drop(b);

        let mut restarted_a = PqChannelSessionManager::new(a_config).unwrap();
        let mut restarted_b = PqChannelSessionManager::new(b_config).unwrap();
        restarted_a.enroll_peer(b_enrollment).unwrap();
        restarted_b.enroll_peer(a_enrollment).unwrap();
        assert_eq!(
            restarted_a.pending_front(&b_peer).map(|(_, value)| value),
            Some(payload)
        );
        let hello = restarted_a.start(b_peer).unwrap();
        let server = restarted_b.accept(a_peer, hello).unwrap();
        let finish = restarted_a.finish(b_peer, server).unwrap();
        restarted_b.complete(a_peer, finish).unwrap();
        restarted_a.confirm_application_ready(&b_peer).unwrap();
        let after_crash = restarted_a
            .seal(&b_peer, PqChannelContentTypeV1::ConsensusVote, &plaintext)
            .unwrap();
        assert_eq!(after_crash.sequence, 0);
        assert_ne!(after_crash.transcript_hash, before_crash.transcript_hash);
        assert_ne!(after_crash.ciphertext, before_crash.ciphertext);
        assert_eq!(restarted_b.open(&a_peer, &after_crash).unwrap(), plaintext);
        assert!(restarted_b.open(&a_peer, &before_crash).is_err());
    }
}
