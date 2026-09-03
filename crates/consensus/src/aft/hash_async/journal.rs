use super::{HashAsyncAction, HashAsyncNode};
use dcrypt::algorithms::aead::chacha20poly1305::ChaCha20Poly1305;
use dcrypt::algorithms::types::Nonce;
use dcrypt::api::traits::symmetric::{DecryptOperation, EncryptOperation, SymmetricCipher};
use fs2::FileExt;
use ioi_types::app::{
    AftAsyncInstanceV1, AftAsyncMessageV1, AftAsyncOrderingDecisionV1, AftAsyncProposalRefV1,
    AftAsyncTranscriptSummaryV1,
};
use ioi_types::codec;
use parity_scale_codec::{Decode, Encode};
use rand::{rngs::OsRng, RngCore};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

const JOURNAL_PROTOCOL_VERSION_V1: u16 = 1;
const JOURNAL_SCHEMA_VERSION_V1: u16 = 3;
const JOURNAL_LEGACY_SCHEMA_VERSION_V1: u16 = 2;
const JOURNAL_MAGIC_V1: [u8; 8] = *b"AFTASJ03";
const JOURNAL_LEGACY_MAGIC_V1: [u8; 8] = *b"AFTASJ02";
const JOURNAL_MAX_BYTES: u64 = 512 * 1024 * 1024;
const JOURNAL_MAX_RECORDS: usize = 2_000_000;
const JOURNAL_KEY_DOMAIN_V1: &[u8] = b"ioi/aft/hash-async-journal-key/v1";
const JOURNAL_ANCHOR_DOMAIN_V1: &[u8] = b"ioi/aft/hash-async-journal-anchor/v1";
const JOURNAL_ERROR_DOMAIN_V1: &[u8] = b"ioi/aft/hash-async-journal-error/v1";
const JOURNAL_HEADER_DOMAIN_V1: &[u8] = b"ioi/aft/hash-async-journal-header/v1";
const JOURNAL_FRAME_DOMAIN_V1: &[u8] = b"ioi/aft/hash-async-journal-frame/v1";
const JOURNAL_EVENT_DOMAIN_V1: &[u8] = b"ioi/aft/hash-async-journal-event/v1";

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
enum JournalEventV1 {
    AdmitVerifiedProposal(AftAsyncProposalRefV1),
    Start(AftAsyncProposalRefV1),
    Message {
        authenticated_sender: u16,
        message: AftAsyncMessageV1,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode)]
enum JournalOutcomeV1 {
    Applied,
    Rejected([u8; 32]),
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
struct JournalRecordV1 {
    event: JournalEventV1,
    outcome: Option<JournalOutcomeV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
struct JournalPlaintextV1 {
    protocol_version: u16,
    schema_version: u16,
    instance_hash: [u8; 32],
    local: u16,
    generation: u64,
    entropy_seed: [u8; 32],
    records: Vec<JournalRecordV1>,
    terminal_checkpoint: Option<JournalTerminalCheckpointV1>,
}

impl Drop for JournalPlaintextV1 {
    fn drop(&mut self) {
        self.entropy_seed.zeroize();
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
struct JournalHeaderPlaintextV1 {
    protocol_version: u16,
    schema_version: u16,
    instance_hash: [u8; 32],
    local: u16,
    entropy_seed: [u8; 32],
    base_generation: u64,
    base_head: [u8; 32],
    terminal_checkpoint: Option<JournalTerminalCheckpointV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
struct LegacyJournalHeaderPlaintextV1 {
    protocol_version: u16,
    schema_version: u16,
    instance_hash: [u8; 32],
    local: u16,
    entropy_seed: [u8; 32],
}

impl Drop for LegacyJournalHeaderPlaintextV1 {
    fn drop(&mut self) {
        self.entropy_seed.zeroize();
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
struct JournalTerminalCheckpointV1 {
    originated_proposal: Option<AftAsyncProposalRefV1>,
    decision: AftAsyncOrderingDecisionV1,
    transcript: AftAsyncTranscriptSummaryV1,
}

impl Drop for JournalHeaderPlaintextV1 {
    fn drop(&mut self) {
        self.entropy_seed.zeroize();
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
struct JournalHeaderEnvelopeV1 {
    magic: [u8; 8],
    protocol_version: u16,
    schema_version: u16,
    instance_hash: [u8; 32],
    local: u16,
    nonce: [u8; 12],
    ciphertext: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
struct JournalFramePlaintextV1 {
    generation: u64,
    record: JournalRecordV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
struct JournalFrameEnvelopeV1 {
    generation: u64,
    previous_head: [u8; 32],
    nonce: [u8; 12],
    ciphertext: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
struct JournalAnchorV1 {
    protocol_version: u16,
    schema_version: u16,
    instance_hash: [u8; 32],
    local: u16,
    generation: u64,
    head: [u8; 32],
    authentication_tag: [u8; 32],
}

struct HashAsyncJournal {
    path: PathBuf,
    anchor_path: PathBuf,
    _anchor_lock: File,
    key: [u8; 32],
    state: JournalPlaintextV1,
    head: [u8; 32],
    event_hashes: std::collections::BTreeSet<[u8; 32]>,
}

impl std::fmt::Debug for HashAsyncJournal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HashAsyncJournal")
            .field("path", &self.path)
            .field("anchor_path", &self.anchor_path)
            .field("generation", &self.state.generation)
            .field("records", &self.state.records.len())
            .field("key_and_plaintext", &"<redacted>")
            .finish()
    }
}

impl Drop for HashAsyncJournal {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

/// Crash-safe hash-only fallback participant. Every input is evaluated on an
/// isolated candidate state. A successful first-seen input is committed before
/// candidate state or resulting actions become observable. Rejected inputs
/// mutate no state and are not journaled; exact duplicates reuse their first
/// durable record. This prevents rejection/retransmission floods from consuming
/// the bounded safety log.
/// The journal is encrypted because it contains private ASKS shares.
/// `anchor_path` must reside on storage outside clonable node snapshots for
/// rollback/clone detection to be meaningful.
#[derive(Debug)]
pub struct DurableHashAsyncNode {
    node: HashAsyncNode,
    journal: HashAsyncJournal,
}

impl DurableHashAsyncNode {
    /// Durably admits a proposal whose exact-q rooted availability evidence
    /// the caller has already verified.
    pub fn admit_verified_proposal(
        &mut self,
        proposal: AftAsyncProposalRefV1,
    ) -> Result<Vec<HashAsyncAction>, String> {
        self.apply(JournalEventV1::AdmitVerifiedProposal(proposal))
    }

    /// Opens or creates one instance/member journal and replays it. A new
    /// journal requires fresh nonzero entropy; an existing journal requires
    /// `None` so restart cannot accidentally replace the persisted entropy.
    /// Returned actions are safe, idempotent replay candidates for the durable
    /// PQ transport outbox.
    pub fn open(
        path: &Path,
        anchor_path: &Path,
        instance: AftAsyncInstanceV1,
        local: u16,
        custody_key: &[u8; 32],
        entropy_for_new: Option<[u8; 32]>,
    ) -> Result<(Self, Vec<HashAsyncAction>), String> {
        let journal = HashAsyncJournal::open(
            path,
            anchor_path,
            &instance,
            local,
            custody_key,
            entropy_for_new,
        )?;
        let node = match journal.state.terminal_checkpoint.clone() {
            Some(checkpoint) => HashAsyncNode::from_terminal_checkpoint(
                instance,
                local,
                journal.state.entropy_seed,
                checkpoint.originated_proposal,
                checkpoint.decision,
                checkpoint.transcript,
            )?,
            None => HashAsyncNode::new(instance, local, journal.state.entropy_seed)?,
        };
        let mut durable = Self { node, journal };
        let actions = durable.replay()?;
        Ok((durable, actions))
    }

    /// Durably starts the local proposal RBC. An exact repeated trigger is
    /// idempotent; a conflicting local proposal is durably rejected.
    pub fn start(
        &mut self,
        proposal: AftAsyncProposalRefV1,
    ) -> Result<Vec<HashAsyncAction>, String> {
        self.apply(JournalEventV1::Start(proposal))
    }

    /// Durably admits one authenticated-channel message before processing it.
    pub fn handle(
        &mut self,
        authenticated_sender: u16,
        message: AftAsyncMessageV1,
    ) -> Result<Vec<HashAsyncAction>, String> {
        self.apply(JournalEventV1::Message {
            authenticated_sender,
            message,
        })
    }

    /// Returns the converged output, if any.
    pub fn output(&self) -> Option<&(AftAsyncOrderingDecisionV1, AftAsyncTranscriptSummaryV1)> {
        self.node.output()
    }

    /// Returns the replayed local proposal reference, if the node had started.
    pub fn originated_proposal(&self) -> Option<&AftAsyncProposalRefV1> {
        self.node.originated_proposal()
    }

    /// Replaces a terminal event WAL with one encrypted, authenticated
    /// checkpoint while preserving the monotonic logical generation/head
    /// already committed by the external anchor. Either the old WAL or the
    /// new checkpoint is valid across a crash at the atomic rename boundary.
    pub fn compact_terminal(&mut self) -> Result<bool, String> {
        let Some((decision, transcript)) = self.node.output().cloned() else {
            return Ok(false);
        };
        if self.journal.state.terminal_checkpoint.is_some() && self.journal.state.records.is_empty()
        {
            return Ok(false);
        }
        self.journal
            .persist_terminal_checkpoint(JournalTerminalCheckpointV1 {
                originated_proposal: self.node.originated_proposal().cloned(),
                decision,
                transcript,
            })?;
        Ok(true)
    }

    /// Reports whether the event WAL has been replaced by its bounded
    /// terminal checkpoint. This is observability only, never authority.
    pub fn terminal_checkpointed(&self) -> bool {
        self.journal.state.terminal_checkpoint.is_some() && self.journal.state.records.is_empty()
    }

    fn replay(&mut self) -> Result<Vec<HashAsyncAction>, String> {
        if self.node.is_terminal() {
            if !self.journal.state.records.is_empty() {
                return Err("terminal hash-async checkpoint retained trailing WAL records".into());
            }
            return Ok(Vec::new());
        }
        let records = self.journal.state.records.clone();
        let mut replay_actions = Vec::new();
        for (index, record) in records.into_iter().enumerate() {
            let result = apply_to_node(&mut self.node, record.event);
            match (record.outcome, result) {
                (Some(JournalOutcomeV1::Applied), Ok(actions)) => {
                    replay_actions.extend(actions);
                }
                (Some(JournalOutcomeV1::Applied), Err(_)) => {
                    return Err("applied hash-async journal record no longer replays".into());
                }
                (Some(JournalOutcomeV1::Rejected(expected)), Err(error))
                    if expected == error_hash(&error)? => {}
                (Some(JournalOutcomeV1::Rejected(_)), _) => {
                    return Err("rejected hash-async journal record changed outcome".into());
                }
                (None, _) => {
                    return Err(format!(
                        "hash-async journal record {index} has no durable outcome"
                    ))
                }
            }
        }
        Ok(replay_actions)
    }

    fn apply(&mut self, event: JournalEventV1) -> Result<Vec<HashAsyncAction>, String> {
        let mut candidate = self.node.clone();
        match apply_to_node(&mut candidate, event.clone()) {
            Ok(actions) => {
                if self.node.is_terminal() {
                    return Ok(actions);
                }
                self.journal
                    .append_complete(event, JournalOutcomeV1::Applied)?;
                self.node = candidate;
                Ok(actions)
            }
            Err(error) => Err(error),
        }
    }
}

fn apply_to_node(
    node: &mut HashAsyncNode,
    event: JournalEventV1,
) -> Result<Vec<HashAsyncAction>, String> {
    match event {
        JournalEventV1::AdmitVerifiedProposal(proposal) => node.admit_verified_proposal(proposal),
        JournalEventV1::Start(proposal) => node.start(proposal),
        JournalEventV1::Message {
            authenticated_sender,
            message,
        } => node.handle(authenticated_sender, message),
    }
}

impl HashAsyncJournal {
    fn open(
        path: &Path,
        anchor_path: &Path,
        instance: &AftAsyncInstanceV1,
        local: u16,
        custody_key: &[u8; 32],
        entropy_for_new: Option<[u8; 32]>,
    ) -> Result<Self, String> {
        instance.validate()?;
        if !instance.geometry.contains(local) || *custody_key == [0; 32] {
            return Err("hash-async journal has invalid membership or custody key".into());
        }
        create_parent(path)?;
        create_parent(anchor_path)?;
        let lock_path = suffixed(anchor_path, ".lock");
        let anchor_lock = open_private(&lock_path, false)?;
        anchor_lock.try_lock_exclusive().map_err(|error| {
            format!(
                "hash-async external anchor {} is already owned: {error}",
                anchor_path.display()
            )
        })?;
        let instance_hash = instance.instance_hash()?;
        let key = derive_key(custody_key, instance_hash, local)?;
        let state_exists = path.exists();
        let anchor_exists = anchor_path.exists();
        if state_exists != anchor_exists {
            return Err("hash-async journal and external anchor presence differ".into());
        }
        let journal = if state_exists {
            if entropy_for_new.is_some() {
                return Err("existing hash-async journal refuses replacement entropy".into());
            }
            let (state, head, previous_head, valid_len, file_len) =
                load_wal(path, instance_hash, local, &key)?;
            let anchor = read_anchor(anchor_path)?;
            validate_anchor(&anchor, instance_hash, local, &key)?;
            if anchor.generation > state.generation {
                return Err("hash-async journal rollback detected by external anchor".into());
            }
            if state.generation > anchor.generation.saturating_add(1) {
                return Err("hash-async journal/anchor generation gap is invalid".into());
            }
            if (state.generation == anchor.generation && head != anchor.head)
                || (state.generation == anchor.generation.saturating_add(1)
                    && previous_head != anchor.head)
            {
                return Err("hash-async journal head conflicts with external anchor".into());
            }
            if valid_len < file_len {
                if state.generation != anchor.generation {
                    return Err(
                        "hash-async journal has an ambiguous torn frame beyond its anchor".into(),
                    );
                }
                truncate_file(path, valid_len)?;
            }
            let event_hashes = collect_event_hashes(&state.records)?;
            Self {
                path: path.to_path_buf(),
                anchor_path: anchor_path.to_path_buf(),
                _anchor_lock: anchor_lock,
                key,
                state,
                head,
                event_hashes,
            }
        } else {
            let entropy_seed = entropy_for_new.ok_or_else(|| {
                "new hash-async journal requires caller-supplied OS entropy".to_string()
            })?;
            if entropy_seed == [0; 32] {
                return Err("new hash-async journal refuses empty entropy".into());
            }
            let state = JournalPlaintextV1 {
                protocol_version: JOURNAL_PROTOCOL_VERSION_V1,
                schema_version: JOURNAL_SCHEMA_VERSION_V1,
                instance_hash,
                local,
                generation: 0,
                entropy_seed,
                records: Vec::new(),
                terminal_checkpoint: None,
            };
            let mut journal = Self {
                path: path.to_path_buf(),
                anchor_path: anchor_path.to_path_buf(),
                _anchor_lock: anchor_lock,
                key,
                state,
                head: [0; 32],
                event_hashes: std::collections::BTreeSet::new(),
            };
            journal.persist_header()?;
            persist_anchor(anchor_path, &journal.anchor()?)?;
            journal
        };
        journal.validate_state(instance_hash, local)?;
        let anchor = read_anchor(anchor_path)?;
        if journal.state.generation == anchor.generation.saturating_add(1) {
            persist_anchor(anchor_path, &journal.anchor()?)?;
        }
        Ok(journal)
    }

    fn validate_state(&self, instance_hash: [u8; 32], local: u16) -> Result<(), String> {
        if self.state.protocol_version != JOURNAL_PROTOCOL_VERSION_V1
            || !matches!(
                self.state.schema_version,
                JOURNAL_LEGACY_SCHEMA_VERSION_V1 | JOURNAL_SCHEMA_VERSION_V1
            )
            || self.state.instance_hash != instance_hash
            || self.state.local != local
            || self.state.entropy_seed == [0; 32]
            || self.state.records.len() > JOURNAL_MAX_RECORDS
            || (self.state.terminal_checkpoint.is_some() && !self.state.records.is_empty())
        {
            return Err("hash-async journal plaintext is invalid or out of scope".into());
        }
        Ok(())
    }

    fn append_complete(
        &mut self,
        event: JournalEventV1,
        outcome: JournalOutcomeV1,
    ) -> Result<usize, String> {
        let durable_event_hash = event_hash(&event)?;
        if self.event_hashes.contains(&durable_event_hash) {
            return Ok(self.state.records.len());
        }
        if self.state.records.len() >= JOURNAL_MAX_RECORDS {
            return Err("hash-async journal record limit exhausted".into());
        }
        let index = self.state.records.len();
        let record = JournalRecordV1 {
            event,
            outcome: Some(outcome),
        };
        let generation = self
            .state
            .generation
            .checked_add(1)
            .ok_or_else(|| "hash-async journal generation exhausted".to_string())?;
        let (frame, head) = encrypt_frame(&self.key, generation, self.head, &record)?;
        append_frame(&self.path, &frame)?;
        self.state.records.push(record);
        self.state.generation = generation;
        self.head = head;
        persist_anchor(&self.anchor_path, &self.anchor()?)?;
        self.event_hashes.insert(durable_event_hash);
        Ok(index)
    }

    fn persist_header(&mut self) -> Result<(), String> {
        let plaintext = codec::to_bytes_canonical(&JournalHeaderPlaintextV1 {
            protocol_version: self.state.protocol_version,
            schema_version: self.state.schema_version,
            instance_hash: self.state.instance_hash,
            local: self.state.local,
            entropy_seed: self.state.entropy_seed,
            base_generation: 0,
            base_head: [0; 32],
            terminal_checkpoint: None,
        })?;
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let cipher = ChaCha20Poly1305::new(&self.key);
        let ciphertext = SymmetricCipher::encrypt(&cipher)
            .with_nonce(&Nonce::new(nonce_bytes))
            .encrypt(&plaintext)
            .map_err(|error| format!("hash-async journal encryption failed: {error}"))?;
        let envelope = JournalHeaderEnvelopeV1 {
            magic: JOURNAL_MAGIC_V1,
            protocol_version: JOURNAL_PROTOCOL_VERSION_V1,
            schema_version: JOURNAL_SCHEMA_VERSION_V1,
            instance_hash: self.state.instance_hash,
            local: self.state.local,
            nonce: nonce_bytes,
            ciphertext: ciphertext.as_ref().to_vec(),
        };
        let encoded = codec::to_bytes_canonical(&envelope)?;
        self.head = header_hash(&envelope)?;
        let length = u32::try_from(encoded.len())
            .map_err(|_| "hash-async journal header is too large".to_string())?;
        let mut file = Vec::with_capacity(4 + encoded.len());
        file.extend_from_slice(&length.to_le_bytes());
        file.extend_from_slice(&encoded);
        persist_atomic(&self.path, &file)
    }

    fn persist_terminal_checkpoint(
        &mut self,
        checkpoint: JournalTerminalCheckpointV1,
    ) -> Result<(), String> {
        checkpoint.decision.validate()?;
        checkpoint
            .transcript
            .validate(&checkpoint.decision.instance)?;
        if checkpoint.decision.transcript_root
            != checkpoint
                .transcript
                .transcript_root(&checkpoint.decision.instance)?
        {
            return Err("hash-async checkpoint decision/transcript binding is invalid".into());
        }
        let plaintext = codec::to_bytes_canonical(&JournalHeaderPlaintextV1 {
            protocol_version: JOURNAL_PROTOCOL_VERSION_V1,
            schema_version: JOURNAL_SCHEMA_VERSION_V1,
            instance_hash: self.state.instance_hash,
            local: self.state.local,
            entropy_seed: self.state.entropy_seed,
            base_generation: self.state.generation,
            base_head: self.head,
            terminal_checkpoint: Some(checkpoint.clone()),
        })?;
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);
        let cipher = ChaCha20Poly1305::new(&self.key);
        let ciphertext = SymmetricCipher::encrypt(&cipher)
            .with_nonce(&Nonce::new(nonce))
            .encrypt(&plaintext)
            .map_err(|error| format!("hash-async checkpoint encryption failed: {error}"))?;
        let envelope = JournalHeaderEnvelopeV1 {
            magic: JOURNAL_MAGIC_V1,
            protocol_version: JOURNAL_PROTOCOL_VERSION_V1,
            schema_version: JOURNAL_SCHEMA_VERSION_V1,
            instance_hash: self.state.instance_hash,
            local: self.state.local,
            nonce,
            ciphertext: ciphertext.as_ref().to_vec(),
        };
        let encoded = codec::to_bytes_canonical(&envelope)?;
        let length = u32::try_from(encoded.len())
            .map_err(|_| "hash-async checkpoint header is too large".to_string())?;
        let mut file = Vec::with_capacity(4 + encoded.len());
        file.extend_from_slice(&length.to_le_bytes());
        file.extend_from_slice(&encoded);
        // The external anchor already commits `generation` and `head`. The
        // replacement preserves both logical values and is atomic, so no
        // second cross-device commit window is introduced.
        persist_atomic(&self.path, &file)?;
        self.state.schema_version = JOURNAL_SCHEMA_VERSION_V1;
        self.state.records.clear();
        self.state.terminal_checkpoint = Some(checkpoint);
        self.event_hashes.clear();
        Ok(())
    }

    fn anchor(&self) -> Result<JournalAnchorV1, String> {
        let mut anchor = JournalAnchorV1 {
            protocol_version: JOURNAL_PROTOCOL_VERSION_V1,
            schema_version: JOURNAL_SCHEMA_VERSION_V1,
            instance_hash: self.state.instance_hash,
            local: self.state.local,
            generation: self.state.generation,
            head: self.head,
            authentication_tag: [0; 32],
        };
        anchor.authentication_tag = anchor_tag(&self.key, &anchor)?;
        Ok(anchor)
    }
}

fn derive_key(
    custody_key: &[u8; 32],
    instance_hash: [u8; 32],
    local: u16,
) -> Result<[u8; 32], String> {
    let material = codec::to_bytes_canonical(&(
        JOURNAL_KEY_DOMAIN_V1.to_vec(),
        custody_key,
        instance_hash,
        local,
    ))?;
    ioi_crypto::algorithms::hash::sha256(material).map_err(|error| error.to_string())
}

fn error_hash(error: &str) -> Result<[u8; 32], String> {
    let material = codec::to_bytes_canonical(&(JOURNAL_ERROR_DOMAIN_V1.to_vec(), error))?;
    ioi_crypto::algorithms::hash::sha256(material).map_err(|failure| failure.to_string())
}

fn event_hash(event: &JournalEventV1) -> Result<[u8; 32], String> {
    let material = codec::to_bytes_canonical(&(JOURNAL_EVENT_DOMAIN_V1.to_vec(), event))?;
    ioi_crypto::algorithms::hash::sha256(material).map_err(|failure| failure.to_string())
}

fn collect_event_hashes(
    records: &[JournalRecordV1],
) -> Result<std::collections::BTreeSet<[u8; 32]>, String> {
    records
        .iter()
        .filter(|record| record.outcome == Some(JournalOutcomeV1::Applied))
        .map(|record| event_hash(&record.event))
        .collect()
}

fn anchor_tag(key: &[u8; 32], anchor: &JournalAnchorV1) -> Result<[u8; 32], String> {
    let material = codec::to_bytes_canonical(&(
        JOURNAL_ANCHOR_DOMAIN_V1.to_vec(),
        key,
        anchor.protocol_version,
        anchor.schema_version,
        anchor.instance_hash,
        anchor.local,
        anchor.generation,
        anchor.head,
    ))?;
    ioi_crypto::algorithms::hash::sha256(material).map_err(|error| error.to_string())
}

fn load_wal(
    path: &Path,
    instance_hash: [u8; 32],
    local: u16,
    key: &[u8; 32],
) -> Result<(JournalPlaintextV1, [u8; 32], [u8; 32], u64, u64), String> {
    let bytes = read_bounded(path)?;
    if bytes.len() < 4 {
        return Err("hash-async journal header length is truncated".into());
    }
    let header_len = u32::from_le_bytes(bytes[..4].try_into().expect("four bytes")) as usize;
    let header_end = 4usize
        .checked_add(header_len)
        .ok_or_else(|| "hash-async journal header length overflow".to_string())?;
    if header_end > bytes.len() {
        return Err("hash-async journal header is truncated".into());
    }
    let envelope = codec::from_bytes_canonical::<JournalHeaderEnvelopeV1>(&bytes[4..header_end])?;
    let current_envelope =
        envelope.magic == JOURNAL_MAGIC_V1 && envelope.schema_version == JOURNAL_SCHEMA_VERSION_V1;
    let legacy_envelope = envelope.magic == JOURNAL_LEGACY_MAGIC_V1
        && envelope.schema_version == JOURNAL_LEGACY_SCHEMA_VERSION_V1;
    if (!current_envelope && !legacy_envelope)
        || envelope.protocol_version != JOURNAL_PROTOCOL_VERSION_V1
        || envelope.instance_hash != instance_hash
        || envelope.local != local
    {
        return Err("hash-async journal envelope is invalid or out of scope".into());
    }
    let physical_header_hash = header_hash(&envelope)?;
    let cipher = ChaCha20Poly1305::new(key);
    let ciphertext = dcrypt::api::types::Ciphertext::new(envelope.ciphertext);
    let plaintext = SymmetricCipher::decrypt(&cipher)
        .with_nonce(&Nonce::new(envelope.nonce))
        .decrypt(&ciphertext)
        .map_err(|_| "hash-async journal authentication failed".to_string())?;
    let (
        header_protocol,
        header_schema,
        header_instance,
        header_local,
        entropy_seed,
        generation,
        mut head,
        terminal_checkpoint,
    ) = if current_envelope {
        let header = codec::from_bytes_canonical::<JournalHeaderPlaintextV1>(&plaintext)?;
        let logical_head = if header.base_generation == 0 {
            if header.base_head != [0; 32] || header.terminal_checkpoint.is_some() {
                return Err("fresh hash-async journal header has checkpoint state".into());
            }
            physical_header_hash
        } else {
            if header.base_head == [0; 32] || header.terminal_checkpoint.is_none() {
                return Err("hash-async checkpoint header lacks its logical anchor".into());
            }
            header.base_head
        };
        (
            header.protocol_version,
            header.schema_version,
            header.instance_hash,
            header.local,
            header.entropy_seed,
            header.base_generation,
            logical_head,
            header.terminal_checkpoint.clone(),
        )
    } else {
        let header = codec::from_bytes_canonical::<LegacyJournalHeaderPlaintextV1>(&plaintext)?;
        (
            header.protocol_version,
            header.schema_version,
            header.instance_hash,
            header.local,
            header.entropy_seed,
            0,
            physical_header_hash,
            None,
        )
    };
    if header_protocol != JOURNAL_PROTOCOL_VERSION_V1
        || header_schema != envelope.schema_version
        || header_instance != instance_hash
        || header_local != local
        || entropy_seed == [0; 32]
    {
        return Err("hash-async journal plaintext header is invalid or out of scope".into());
    }
    let mut state = JournalPlaintextV1 {
        protocol_version: header_protocol,
        schema_version: header_schema,
        instance_hash,
        local,
        generation,
        entropy_seed,
        records: Vec::new(),
        terminal_checkpoint,
    };
    let mut cursor = header_end;
    let mut previous_head = head;
    while cursor < bytes.len() {
        if bytes.len() - cursor < 4 {
            break;
        }
        let frame_len =
            u32::from_le_bytes(bytes[cursor..cursor + 4].try_into().expect("four bytes")) as usize;
        let frame_start = cursor + 4;
        let frame_end = frame_start
            .checked_add(frame_len)
            .ok_or_else(|| "hash-async journal frame length overflow".to_string())?;
        if frame_end > bytes.len() {
            break;
        }
        let frame =
            codec::from_bytes_canonical::<JournalFrameEnvelopeV1>(&bytes[frame_start..frame_end])?;
        let expected_generation = state
            .generation
            .checked_add(1)
            .ok_or_else(|| "hash-async journal generation exhausted".to_string())?;
        if frame.generation != expected_generation || frame.previous_head != head {
            return Err("hash-async journal frame chain is invalid".into());
        }
        let plaintext = decrypt_frame(key, &frame)?;
        if plaintext.generation != frame.generation || plaintext.record.outcome.is_none() {
            return Err("hash-async journal frame plaintext is invalid".into());
        }
        previous_head = head;
        head = frame_hash(&frame)?;
        state.generation = frame.generation;
        state.records.push(plaintext.record);
        if state.records.len() > JOURNAL_MAX_RECORDS {
            return Err("hash-async journal record limit exceeded".into());
        }
        cursor = frame_end;
    }
    Ok((
        state,
        head,
        previous_head,
        u64::try_from(cursor).map_err(|_| "journal offset overflow".to_string())?,
        u64::try_from(bytes.len()).map_err(|_| "journal length overflow".to_string())?,
    ))
}

fn encrypt_frame(
    key: &[u8; 32],
    generation: u64,
    previous_head: [u8; 32],
    record: &JournalRecordV1,
) -> Result<(JournalFrameEnvelopeV1, [u8; 32]), String> {
    let plaintext = codec::to_bytes_canonical(&JournalFramePlaintextV1 {
        generation,
        record: record.clone(),
    })?;
    let mut nonce = [0; 12];
    OsRng.fill_bytes(&mut nonce);
    let cipher = ChaCha20Poly1305::new(key);
    let ciphertext = SymmetricCipher::encrypt(&cipher)
        .with_nonce(&Nonce::new(nonce))
        .encrypt(&plaintext)
        .map_err(|error| format!("hash-async journal frame encryption failed: {error}"))?;
    let frame = JournalFrameEnvelopeV1 {
        generation,
        previous_head,
        nonce,
        ciphertext: ciphertext.as_ref().to_vec(),
    };
    let head = frame_hash(&frame)?;
    Ok((frame, head))
}

fn decrypt_frame(
    key: &[u8; 32],
    frame: &JournalFrameEnvelopeV1,
) -> Result<JournalFramePlaintextV1, String> {
    let cipher = ChaCha20Poly1305::new(key);
    let ciphertext = dcrypt::api::types::Ciphertext::new(frame.ciphertext.clone());
    let plaintext = SymmetricCipher::decrypt(&cipher)
        .with_nonce(&Nonce::new(frame.nonce))
        .decrypt(&ciphertext)
        .map_err(|_| "hash-async journal frame authentication failed".to_string())?;
    codec::from_bytes_canonical(&plaintext)
}

fn frame_hash(frame: &JournalFrameEnvelopeV1) -> Result<[u8; 32], String> {
    let material = codec::to_bytes_canonical(&(
        JOURNAL_FRAME_DOMAIN_V1.to_vec(),
        frame.generation,
        frame.previous_head,
        frame.nonce,
        &frame.ciphertext,
    ))?;
    ioi_crypto::algorithms::hash::sha256(material).map_err(|error| error.to_string())
}

fn header_hash(header: &JournalHeaderEnvelopeV1) -> Result<[u8; 32], String> {
    let material = codec::to_bytes_canonical(&(
        JOURNAL_HEADER_DOMAIN_V1.to_vec(),
        header.magic,
        header.protocol_version,
        header.schema_version,
        header.instance_hash,
        header.local,
        header.nonce,
        &header.ciphertext,
    ))?;
    ioi_crypto::algorithms::hash::sha256(material).map_err(|error| error.to_string())
}

fn append_frame(path: &Path, frame: &JournalFrameEnvelopeV1) -> Result<(), String> {
    let bytes = codec::to_bytes_canonical(frame)?;
    let length = u32::try_from(bytes.len())
        .map_err(|_| "hash-async journal frame is too large".to_string())?;
    let mut options = OpenOptions::new();
    options.append(true).read(true);
    let mut file = options
        .open(path)
        .map_err(|error| format!("failed to append {}: {error}", path.display()))?;
    file.write_all(&length.to_le_bytes())
        .and_then(|_| file.write_all(&bytes))
        .map_err(|error| format!("failed to append {}: {error}", path.display()))?;
    file.sync_all()
        .map_err(|error| format!("failed to sync {}: {error}", path.display()))
}

fn truncate_file(path: &Path, length: u64) -> Result<(), String> {
    let file = OpenOptions::new()
        .write(true)
        .open(path)
        .map_err(|error| format!("failed to open {} for recovery: {error}", path.display()))?;
    file.set_len(length)
        .and_then(|_| file.sync_all())
        .map_err(|error| {
            format!(
                "failed to truncate {} after torn append: {error}",
                path.display()
            )
        })
}

fn validate_anchor(
    anchor: &JournalAnchorV1,
    instance_hash: [u8; 32],
    local: u16,
    key: &[u8; 32],
) -> Result<(), String> {
    if anchor.protocol_version != JOURNAL_PROTOCOL_VERSION_V1
        || !matches!(
            anchor.schema_version,
            JOURNAL_LEGACY_SCHEMA_VERSION_V1 | JOURNAL_SCHEMA_VERSION_V1
        )
        || anchor.instance_hash != instance_hash
        || anchor.local != local
        || anchor.head == [0; 32]
        || anchor.authentication_tag != anchor_tag(key, anchor)?
    {
        return Err("hash-async external anchor is invalid or out of scope".into());
    }
    Ok(())
}

fn read_anchor(path: &Path) -> Result<JournalAnchorV1, String> {
    codec::from_bytes_canonical(&read_bounded(path)?)
}

fn persist_anchor(path: &Path, anchor: &JournalAnchorV1) -> Result<(), String> {
    persist_atomic(path, &codec::to_bytes_canonical(anchor)?)
}

fn read_bounded(path: &Path) -> Result<Vec<u8>, String> {
    let metadata = std::fs::metadata(path)
        .map_err(|error| format!("failed to inspect {}: {error}", path.display()))?;
    if metadata.len() > JOURNAL_MAX_BYTES {
        return Err(format!(
            "hash-async durable file {} exceeds its byte limit",
            path.display()
        ));
    }
    std::fs::read(path).map_err(|error| format!("failed to read {}: {error}", path.display()))
}

fn persist_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let staged = suffixed(path, ".tmp");
    let mut file = open_private(&staged, true)?;
    file.write_all(bytes)
        .map_err(|error| format!("failed to write {}: {error}", staged.display()))?;
    file.sync_all()
        .map_err(|error| format!("failed to sync {}: {error}", staged.display()))?;
    std::fs::rename(&staged, path)
        .map_err(|error| format!("failed to commit {}: {error}", path.display()))?;
    if let Some(parent) = path.parent() {
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| {
                format!(
                    "failed to sync durable directory {}: {error}",
                    parent.display()
                )
            })?;
    }
    Ok(())
}

fn create_parent(path: &Path) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "hash-async durable path requires a parent directory".to_string())?;
    std::fs::create_dir_all(parent)
        .map_err(|error| format!("failed to create {}: {error}", parent.display()))
}

fn open_private(path: &Path, truncate: bool) -> Result<File, String> {
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
        .map_err(|error| format!("failed to open {}: {error}", path.display()))
}

fn suffixed(path: &Path, suffix: &str) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(suffix);
    PathBuf::from(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aft::hash_async::node::tests_support::{proposal_for, test_instance};
    use std::collections::{BTreeSet, VecDeque};

    fn enqueue_honest(
        queue: &mut VecDeque<(u16, AftAsyncMessageV1)>,
        actions: Vec<HashAsyncAction>,
    ) {
        for action in actions {
            match action {
                HashAsyncAction::Broadcast(message) => {
                    for recipient in 0..3 {
                        queue.push_back((recipient, message.clone()));
                    }
                }
                HashAsyncAction::Send { recipient, message } if recipient < 3 => {
                    queue.push_back((recipient, message));
                }
                HashAsyncAction::Send { .. } | HashAsyncAction::Decide { .. } => {}
            }
        }
    }

    #[test]
    fn encrypted_journal_replays_and_external_anchor_refuses_rollback() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("node.aft");
        let anchor = directory.path().join("external/node.anchor");
        let instance = test_instance();
        let key = [44; 32];
        let (mut node, initial) =
            DurableHashAsyncNode::open(&path, &anchor, instance.clone(), 0, &key, Some([55; 32]))
                .unwrap();
        assert!(initial.is_empty());
        let old_state = std::fs::read(&path).unwrap();
        let actions = node.start(proposal_for(&instance, 0)).unwrap();
        assert!(!actions.is_empty());
        drop(node);

        let (node, replay) =
            DurableHashAsyncNode::open(&path, &anchor, instance.clone(), 0, &key, None).unwrap();
        assert!(!replay.is_empty());
        drop(node);

        std::fs::write(&path, old_state).unwrap();
        let error =
            DurableHashAsyncNode::open(&path, &anchor, instance, 0, &key, None).unwrap_err();
        assert!(error.contains("rollback"));
    }

    #[test]
    fn journal_is_confidential_scope_bound_and_clone_locked() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("node.aft");
        let anchor = directory.path().join("anchor/node.anchor");
        let instance = test_instance();
        let key = [77; 32];
        let (mut node, _) =
            DurableHashAsyncNode::open(&path, &anchor, instance.clone(), 0, &key, Some([88; 32]))
                .unwrap();
        let proposal = proposal_for(&instance, 0);
        node.start(proposal.clone()).unwrap();
        let disk = std::fs::read(&path).unwrap();
        let encoded_proposal = codec::to_bytes_canonical(&proposal).unwrap();
        assert!(!disk
            .windows(encoded_proposal.len())
            .any(|window| window == encoded_proposal));
        assert!(
            DurableHashAsyncNode::open(&path, &anchor, instance.clone(), 0, &key, None).is_err()
        );
        drop(node);
        assert!(
            DurableHashAsyncNode::open(&path, &anchor, instance.clone(), 0, &[78; 32], None)
                .is_err()
        );
        assert!(DurableHashAsyncNode::open(&path, &anchor, instance, 1, &key, None).is_err());
    }

    #[test]
    fn external_anchor_tampering_fails_authentication() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("node.aft");
        let anchor = directory.path().join("external/node.anchor");
        let instance = test_instance();
        let key = [91; 32];
        let (node, _) =
            DurableHashAsyncNode::open(&path, &anchor, instance.clone(), 0, &key, Some([92; 32]))
                .unwrap();
        drop(node);

        let mut forged = read_anchor(&anchor).unwrap();
        forged.generation = forged.generation.saturating_add(1);
        std::fs::write(&anchor, codec::to_bytes_canonical(&forged).unwrap()).unwrap();
        let error =
            DurableHashAsyncNode::open(&path, &anchor, instance, 0, &key, None).unwrap_err();
        assert!(error.contains("anchor"));
    }

    #[test]
    fn append_wal_recovers_only_an_unanchored_torn_tail() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("node.aft");
        let anchor = directory.path().join("external/node.anchor");
        let instance = test_instance();
        let key = [93; 32];
        let (mut node, _) =
            DurableHashAsyncNode::open(&path, &anchor, instance.clone(), 0, &key, Some([94; 32]))
                .unwrap();
        node.start(proposal_for(&instance, 0)).unwrap();
        drop(node);
        let valid_length = std::fs::metadata(&path).unwrap().len();
        let mut file = OpenOptions::new().append(true).open(&path).unwrap();
        file.write_all(&[12, 0, 0]).unwrap();
        file.sync_all().unwrap();
        drop(file);

        let (node, replay) =
            DurableHashAsyncNode::open(&path, &anchor, instance, 0, &key, None).unwrap();
        assert!(!replay.is_empty());
        assert_eq!(std::fs::metadata(&path).unwrap().len(), valid_length);
        drop(node);
    }

    #[test]
    fn complete_frame_before_anchor_crash_is_recovered_exactly_once() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("node.aft");
        let anchor_path = directory.path().join("external/node.anchor");
        let instance = test_instance();
        let custody_key = [103; 32];
        let journal = HashAsyncJournal::open(
            &path,
            &anchor_path,
            &instance,
            0,
            &custody_key,
            Some([104; 32]),
        )
        .unwrap();
        let event = JournalEventV1::Start(proposal_for(&instance, 0));
        let record = JournalRecordV1 {
            event,
            outcome: Some(JournalOutcomeV1::Applied),
        };
        let (frame, _) = encrypt_frame(&journal.key, 1, journal.head, &record).unwrap();
        append_frame(&path, &frame).unwrap();
        // Simulated power loss: the complete frame reached stable storage,
        // but neither in-memory state nor the external anchor advanced.
        drop(journal);

        let (node, replay) =
            DurableHashAsyncNode::open(&path, &anchor_path, instance, 0, &custody_key, None)
                .unwrap();
        assert!(!replay.is_empty());
        assert_eq!(read_anchor(&anchor_path).unwrap().generation, 1);
        drop(node);
    }

    #[test]
    fn duplicate_and_rejected_inputs_do_not_grow_the_safety_log() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("node.aft");
        let anchor = directory.path().join("external/node.anchor");
        let instance = test_instance();
        let key = [101; 32];
        let (mut node, _) =
            DurableHashAsyncNode::open(&path, &anchor, instance.clone(), 0, &key, Some([102; 32]))
                .unwrap();
        let proposal = proposal_for(&instance, 0);
        let actions = node.start(proposal.clone()).unwrap();
        let mut message = actions
            .into_iter()
            .find_map(|action| match action {
                HashAsyncAction::Broadcast(message) => Some(message),
                HashAsyncAction::Send { message, .. } => Some(message),
                HashAsyncAction::Decide { .. } => None,
            })
            .expect("start emits a protocol message");
        let durable_len = std::fs::metadata(&path).unwrap().len();

        assert!(node.start(proposal).unwrap().is_empty());
        assert_eq!(std::fs::metadata(&path).unwrap().len(), durable_len);

        message.instance_hash[0] ^= 1;
        assert!(node.handle(message.sender, message).is_err());
        assert_eq!(std::fs::metadata(&path).unwrap().len(), durable_len);
        assert_eq!(node.journal.state.records.len(), 1);
    }

    #[test]
    fn append_wal_refuses_same_generation_ciphertext_mutation() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("node.aft");
        let anchor = directory.path().join("external/node.anchor");
        let instance = test_instance();
        let key = [95; 32];
        let (mut node, _) =
            DurableHashAsyncNode::open(&path, &anchor, instance.clone(), 0, &key, Some([96; 32]))
                .unwrap();
        node.start(proposal_for(&instance, 0)).unwrap();
        drop(node);

        let mut bytes = std::fs::read(&path).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        std::fs::write(&path, bytes).unwrap();
        assert!(DurableHashAsyncNode::open(&path, &anchor, instance, 0, &key, None).is_err());
    }

    #[test]
    fn append_wal_anchor_binds_the_encrypted_entropy_header() {
        let directory = tempfile::tempdir().unwrap();
        let first_path = directory.path().join("first/node.aft");
        let first_anchor = directory.path().join("external-first/node.anchor");
        let second_path = directory.path().join("second/node.aft");
        let second_anchor = directory.path().join("external-second/node.anchor");
        let instance = test_instance();
        let key = [97; 32];
        let (first, _) = DurableHashAsyncNode::open(
            &first_path,
            &first_anchor,
            instance.clone(),
            0,
            &key,
            Some([98; 32]),
        )
        .unwrap();
        let (second, _) = DurableHashAsyncNode::open(
            &second_path,
            &second_anchor,
            instance.clone(),
            0,
            &key,
            Some([99; 32]),
        )
        .unwrap();
        drop((first, second));

        std::fs::write(&first_path, std::fs::read(&second_path).unwrap()).unwrap();
        assert!(
            DurableHashAsyncNode::open(&first_path, &first_anchor, instance, 0, &key, None)
                .is_err()
        );
    }

    #[test]
    fn legacy_schema_two_journal_resumes_and_advances_under_schema_three() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("node.aft");
        let anchor_path = directory.path().join("external/node.anchor");
        create_parent(&path).unwrap();
        create_parent(&anchor_path).unwrap();
        let instance = test_instance();
        let custody_key = [111; 32];
        let instance_hash = instance.instance_hash().unwrap();
        let key = derive_key(&custody_key, instance_hash, 0).unwrap();
        let entropy_seed = [112; 32];
        let plaintext = codec::to_bytes_canonical(&LegacyJournalHeaderPlaintextV1 {
            protocol_version: JOURNAL_PROTOCOL_VERSION_V1,
            schema_version: JOURNAL_LEGACY_SCHEMA_VERSION_V1,
            instance_hash,
            local: 0,
            entropy_seed,
        })
        .unwrap();
        let nonce = [113; 12];
        let cipher = ChaCha20Poly1305::new(&key);
        let ciphertext = SymmetricCipher::encrypt(&cipher)
            .with_nonce(&Nonce::new(nonce))
            .encrypt(&plaintext)
            .unwrap();
        let envelope = JournalHeaderEnvelopeV1 {
            magic: JOURNAL_LEGACY_MAGIC_V1,
            protocol_version: JOURNAL_PROTOCOL_VERSION_V1,
            schema_version: JOURNAL_LEGACY_SCHEMA_VERSION_V1,
            instance_hash,
            local: 0,
            nonce,
            ciphertext: ciphertext.as_ref().to_vec(),
        };
        let encoded = codec::to_bytes_canonical(&envelope).unwrap();
        let mut bytes = Vec::with_capacity(4 + encoded.len());
        bytes.extend_from_slice(&(encoded.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&encoded);
        persist_atomic(&path, &bytes).unwrap();
        let mut anchor = JournalAnchorV1 {
            protocol_version: JOURNAL_PROTOCOL_VERSION_V1,
            schema_version: JOURNAL_LEGACY_SCHEMA_VERSION_V1,
            instance_hash,
            local: 0,
            generation: 0,
            head: header_hash(&envelope).unwrap(),
            authentication_tag: [0; 32],
        };
        anchor.authentication_tag = anchor_tag(&key, &anchor).unwrap();
        persist_anchor(&anchor_path, &anchor).unwrap();

        let (mut node, replay) = DurableHashAsyncNode::open(
            &path,
            &anchor_path,
            instance.clone(),
            0,
            &custody_key,
            None,
        )
        .unwrap();
        assert!(replay.is_empty());
        assert!(!node.start(proposal_for(&instance, 0)).unwrap().is_empty());
        drop(node);
        let (reopened, replay) =
            DurableHashAsyncNode::open(&path, &anchor_path, instance, 0, &custody_key, None)
                .unwrap();
        assert!(!replay.is_empty());
        drop(reopened);
        assert_eq!(read_anchor(&anchor_path).unwrap().schema_version, 3);
    }

    #[test]
    fn adverse_schedule_survives_repeated_mid_protocol_restart() {
        let directory = tempfile::tempdir().unwrap();
        let instance = test_instance();
        let custody_key = [121; 32];
        let paths = (0..3)
            .map(|local| {
                (
                    directory.path().join(format!("node-{local}.aft")),
                    directory.path().join(format!("anchor-{local}.aft")),
                )
            })
            .collect::<Vec<_>>();
        let mut nodes = paths
            .iter()
            .enumerate()
            .map(|(local, (journal, anchor))| {
                DurableHashAsyncNode::open(
                    journal,
                    anchor,
                    instance.clone(),
                    local as u16,
                    &custody_key,
                    Some([local as u8 + 1; 32]),
                )
                .map(|(node, _)| Some(node))
                .unwrap()
            })
            .collect::<Vec<_>>();
        let proposals = (0..3)
            .map(|proposer| proposal_for(&instance, proposer))
            .collect::<Vec<_>>();
        for node in &mut nodes {
            for proposal in &proposals {
                assert!(node
                    .as_mut()
                    .unwrap()
                    .admit_verified_proposal(proposal.clone())
                    .unwrap()
                    .is_empty());
            }
        }
        let mut queue = VecDeque::new();
        for local in 0..3 {
            enqueue_honest(
                &mut queue,
                nodes[local]
                    .as_mut()
                    .unwrap()
                    .start(proposals[local].clone())
                    .unwrap(),
            );
        }

        let restart_at = [50_usize, 200, 400];
        let mut deliveries = 0_usize;
        let mut reverse = false;
        while nodes
            .iter()
            .any(|node| node.as_ref().unwrap().output().is_none())
            && deliveries < 100_000
        {
            if restart_at.contains(&deliveries) {
                drop(nodes[0].take().unwrap());
                let (reopened, replay) = DurableHashAsyncNode::open(
                    &paths[0].0,
                    &paths[0].1,
                    instance.clone(),
                    0,
                    &custody_key,
                    None,
                )
                .unwrap();
                nodes[0] = Some(reopened);
                enqueue_honest(&mut queue, replay);
            }
            let (recipient, message) = if reverse {
                queue.pop_back()
            } else {
                queue.pop_front()
            }
            .expect("restart schedule quiesced before decision");
            reverse = !reverse;
            let sender = message.sender;
            let actions = nodes[recipient as usize]
                .as_mut()
                .unwrap()
                .handle(sender, message)
                .unwrap();
            enqueue_honest(&mut queue, actions);
            deliveries += 1;
        }
        assert!(deliveries < 100_000, "restart schedule exceeded bound");
        let roots = nodes
            .iter()
            .map(|node| node.as_ref().unwrap().output().unwrap().0.ordering_root)
            .collect::<BTreeSet<_>>();
        assert_eq!(roots.len(), 1);
    }
}
