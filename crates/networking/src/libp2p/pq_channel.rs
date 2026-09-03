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
};
use ioi_types::app::{AccountId, AftAsyncCarrierV1};
use ioi_types::codec;
use libp2p::PeerId;
use parity_scale_codec::{Decode, Encode};
use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use super::sync::PqConsensusPayloadV1;

const PQ_OUTBOX_PROTOCOL_VERSION: u16 = 1;
const PQ_OUTBOX_SCHEMA_VERSION: u16 = 2;
const PQ_OUTBOX_MESSAGE_ID_DOMAIN: &[u8] = b"ioi/aft/pq-outbox-message/v2";
const PQ_OUTBOX_PER_RECIPIENT_MAX: usize = 1_024;

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
    entries: Vec<PqOutboxEntryV2>,
}

struct PqDurableOutbox {
    path: PathBuf,
    _lock: File,
    state: PqOutboxStateV2,
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

fn persist_outbox(path: &Path, state: &PqOutboxStateV2) -> Result<()> {
    let bytes = codec::to_bytes_canonical(state).map_err(anyhow::Error::msg)?;
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
    file.write_all(&bytes)?;
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
        std::fs::create_dir_all(parent)?;
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
        let state = if local.outbox_path.exists() {
            let bytes = std::fs::read(&local.outbox_path)?;
            let decoded = codec::from_bytes_canonical::<PqOutboxStateV2>(&bytes)
                .map_err(anyhow::Error::msg)?;
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
        let outbox = Self {
            path: local.outbox_path.clone(),
            _lock: lock,
            state,
        };
        outbox.validate_entries()?;
        Ok(outbox)
    }

    fn validate_entries(&self) -> Result<()> {
        let mut seen = std::collections::BTreeSet::new();
        let mut per_recipient: HashMap<AccountId, usize> = HashMap::new();
        for entry in &self.state.entries {
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
        }
        Ok(())
    }

    fn message_id(&self, recipient: AccountId, payload: &PqConsensusPayloadV1) -> Result<[u8; 32]> {
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

    fn enqueue(&mut self, recipient: AccountId, payload: PqConsensusPayloadV1) -> Result<[u8; 32]> {
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
            return Ok(message_id);
        }
        if self
            .state
            .entries
            .iter()
            .filter(|entry| entry.recipient_account_id == recipient)
            .count()
            >= PQ_OUTBOX_PER_RECIPIENT_MAX
        {
            return Err(anyhow!(
                "PQ durable outbox is full for recipient; refusing to discard protected consensus evidence"
            ));
        }
        let mut next = self.state.clone();
        next.entries.push(PqOutboxEntryV2 {
            recipient_account_id: recipient,
            message_id,
            payload,
        });
        persist_outbox(&self.path, &next)?;
        self.state = next;
        Ok(message_id)
    }

    fn front(&self, recipient: AccountId) -> Option<([u8; 32], PqConsensusPayloadV1)> {
        self.state
            .entries
            .iter()
            .find(|entry| entry.recipient_account_id == recipient)
            .map(|entry| (entry.message_id, entry.payload.clone()))
    }

    fn acknowledge(&mut self, recipient: AccountId, message_id: [u8; 32]) -> Result<()> {
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
        persist_outbox(&self.path, &next)?;
        self.state = next;
        Ok(())
    }

    fn retire_aft_async_instance(
        &mut self,
        instance_hash: [u8; 32],
    ) -> Result<std::collections::BTreeSet<[u8; 32]>> {
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
        persist_outbox(&self.path, &next)?;
        self.state = next;
        Ok(retired)
    }

    fn recipients(&self) -> Vec<AccountId> {
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
    enrollments: HashMap<PeerId, PqPeerEnrollment>,
    pending_initiators: HashMap<PeerId, PqChannelInitiatorState>,
    pending_responders: HashMap<PeerId, PqChannelResponderState>,
    sessions: HashMap<PeerId, EstablishedSession>,
    outbox: PqDurableOutbox,
}

fn transport_binding(peer: &PeerId) -> Result<[u8; 32]> {
    ioi_crypto::algorithms::hash::sha256(peer.to_bytes())
        .map_err(|error| anyhow!(error.to_string()))
}

impl PqChannelSessionManager {
    pub fn new(local: PqChannelLocalConfig) -> Result<Self> {
        if local.configuration_hash == [0; 32] {
            return Err(anyhow!("PQ channel configuration hash is absent"));
        }
        let outbox = PqDurableOutbox::open(&local)?;
        Ok(Self {
            local,
            enrollments: HashMap::new(),
            pending_initiators: HashMap::new(),
            pending_responders: HashMap::new(),
            sessions: HashMap::new(),
            outbox,
        })
    }

    /// Installs one rooted peer enrollment. Changing it tears down all state
    /// for that carrier before the new key can be used.
    pub fn enroll_peer(&mut self, enrollment: PqPeerEnrollment) -> Result<()> {
        if enrollment.peer_id == self.local.peer_id
            || enrollment.account_id == self.local.account_id
        {
            return Err(anyhow!("PQ peer enrollment aliases the local endpoint"));
        }
        // Status synchronization refreshes rooted peer metadata repeatedly.
        // Treat an identical refresh as idempotent: tearing down an established
        // or in-flight session here can indefinitely suppress strict-PQ traffic
        // while status responses continue to arrive.
        if self.enrollments.get(&enrollment.peer_id) == Some(&enrollment) {
            return Ok(());
        }
        if self.enrollments.iter().any(|(peer, existing)| {
            *peer != enrollment.peer_id && existing.account_id == enrollment.account_id
        }) {
            return Err(anyhow!(
                "PQ peer enrollment assigns one rooted account to multiple carriers"
            ));
        }
        self.disconnect(&enrollment.peer_id);
        self.enrollments.insert(enrollment.peer_id, enrollment);
        Ok(())
    }

    fn enrollment(&self, peer: &PeerId) -> Result<&PqPeerEnrollment> {
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
        let session = self
            .sessions
            .get_mut(peer)
            .ok_or_else(|| anyhow!("PQ channel has no established keys for peer"))?;
        session.application_ready = true;
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

    pub fn peer_for_account(&self, account: AccountId) -> Option<PeerId> {
        self.enrollments
            .iter()
            .find_map(|(peer, enrollment)| (enrollment.account_id == account).then_some(*peer))
    }

    /// Durably queues for a rooted account before its transient carrier is
    /// necessarily known. Enrollment later makes the entry drainable.
    pub fn enqueue_for_account(
        &mut self,
        recipient: AccountId,
        payload: PqConsensusPayloadV1,
    ) -> Result<[u8; 32]> {
        self.outbox.enqueue(recipient, payload)
    }

    pub fn enqueue(&mut self, peer: PeerId, payload: PqConsensusPayloadV1) -> Result<[u8; 32]> {
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
        self.pending_initiators.remove(peer);
        self.pending_responders.remove(peer);
        self.sessions.remove(peer);
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
        AftAsyncProposalDescriptorV1, SignatureSuite, AFT_ASYNC_PROTOCOL_VERSION_V1,
        AFT_ASYNC_SCHEMA_VERSION_V1,
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
        a.enroll_peer(b_enrollment).unwrap();
        b.enroll_peer(a_enrollment).unwrap();

        let old_hello = a.start(b_peer).unwrap();
        let old_server = b.accept(a_peer, old_hello).unwrap();

        // Model both endpoints observing a carrier disconnect and starting a
        // fresh transcript while the old response is still in an event queue.
        a.disconnect(&b_peer);
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

        let mut reopened = PqChannelSessionManager::new(reopened_config).unwrap();
        assert!(reopened.pending_peers().is_empty());
        reopened.enroll_peer(enrollment).unwrap();
        assert_eq!(reopened.pending_peers(), vec![remote.peer_id]);
        assert_eq!(
            reopened.pending_front(&remote.peer_id),
            Some((message_id, payload))
        );
    }

    #[test]
    fn enrollment_refuses_one_rooted_account_on_multiple_carriers() {
        let temp = tempfile::tempdir().unwrap();
        let config = local_config(44, temp.path().join("unique-account.outbox"));
        let remote = local_config(45, temp.path().join("remote-unique-account.outbox"));
        let mut manager = PqChannelSessionManager::new(config).unwrap();
        manager
            .enroll_peer(PqPeerEnrollment {
                peer_id: remote.peer_id,
                account_id: remote.account_id,
                identity_key_hash: remote.identity_key_hash,
            })
            .unwrap();
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
