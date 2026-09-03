//! Mutually authenticated post-quantum channel handshake for AFT.
//!
//! This module is the cryptographic core of `aft-pq-channel-v1`. It does not
//! claim that an arbitrary carrier (including libp2p Noise) is PQ: callers must
//! gate application records on a completed handshake and protect those records
//! with the returned directional traffic keys.

use crate::algorithms::hash::sha256;
use crate::kem::hybrid::{HybridEncapsulated, HybridKEM, HybridPrivateKey};
use crate::security::SecurityLevel;
use crate::sign::dilithium::{MldsaKeyPair, MldsaPublicKey, MldsaSignature};
use anyhow::{anyhow, Result};
use dcrypt::algorithms::aead::chacha20poly1305::ChaCha20Poly1305;
use dcrypt::algorithms::hash::Sha256;
use dcrypt::algorithms::mac::Hmac;
use dcrypt::api::traits::symmetric::{DecryptOperation, EncryptOperation};
use dcrypt::api::traits::SymmetricCipher;
use ioi_api::crypto::{
    Encapsulated, KeyEncapsulation, SerializableKey, SigningKeyPair, VerifyingKey,
};
use ioi_types::app::{account_id_from_key_material, AccountId, SignatureSuite};
use ioi_types::codec;
use parity_scale_codec::{Decode, Encode};
use rand::RngCore as _;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

pub const AFT_PQ_CHANNEL_PROTOCOL_VERSION: u16 = 1;
pub const AFT_PQ_CHANNEL_SCHEMA_VERSION: u16 = 1;
pub const AFT_PQ_CHANNEL_PROFILE: &[u8] = b"aft-pq-channel-v1";
const CLIENT_HELLO_DOMAIN: &[u8] = b"ioi::aft::pq-channel::client-hello::v1\0";
const SERVER_HELLO_DOMAIN: &[u8] = b"ioi::aft::pq-channel::server-hello::v1\0";
const CLIENT_FINISH_DOMAIN: &[u8] = b"ioi::aft::pq-channel::client-finish::v1\0";
const COMPLETION_EVIDENCE_DOMAIN: &[u8] = b"ioi::aft::pq-channel::completion-evidence::v1\0";
const KDF_EXTRACT_DOMAIN: &[u8] = b"ioi::aft::pq-channel::extract::v1\0";
const KDF_EXPAND_DOMAIN: &[u8] = b"ioi::aft::pq-channel::expand::v1\0";
const RECORD_AAD_DOMAIN: &[u8] = b"ioi::aft::pq-channel::record::v1\0";
const MAX_RECORD_PLAINTEXT: usize = 16 * 1024 * 1024;

/// Rooted scope and carrier bindings for exactly one pairwise session.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, Serialize, Deserialize)]
pub struct PqChannelScopeV1 {
    pub network_id: [u8; 32],
    pub configuration_hash: [u8; 32],
    pub epoch: u64,
    pub initiator: AccountId,
    pub responder: AccountId,
    /// Hash of the initiator's carrier endpoint identity. This prevents
    /// splicing but grants no authority by itself.
    pub initiator_transport_binding: [u8; 32],
    /// Hash of the responder's carrier endpoint identity.
    pub responder_transport_binding: [u8; 32],
}

impl PqChannelScopeV1 {
    fn validate(&self) -> Result<()> {
        if self.initiator == self.responder {
            return Err(anyhow!("PQ channel endpoints must be distinct members"));
        }
        if self.configuration_hash == [0; 32] {
            return Err(anyhow!("PQ channel configuration hash is absent"));
        }
        if self.initiator_transport_binding == self.responder_transport_binding {
            return Err(anyhow!(
                "PQ channel carrier endpoint bindings are not distinct"
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, Serialize, Deserialize)]
pub struct PqChannelClientHelloV1 {
    pub protocol_version: u16,
    pub schema_version: u16,
    pub scope: PqChannelScopeV1,
    pub nonce: [u8; 32],
    /// Ephemeral ECDH-P256 + ML-KEM-768 public key. The ML-KEM contribution is
    /// load-bearing; ECDH is defense in depth.
    pub kem_public_key: Vec<u8>,
    pub identity_suite: SignatureSuite,
    pub identity_public_key: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, Serialize, Deserialize)]
pub struct PqChannelServerHelloV1 {
    pub protocol_version: u16,
    pub schema_version: u16,
    pub client_hello_hash: [u8; 32],
    pub nonce: [u8; 32],
    pub kem_ciphertext: Vec<u8>,
    pub identity_suite: SignatureSuite,
    pub identity_public_key: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, Serialize, Deserialize)]
pub struct PqChannelClientFinishV1 {
    pub protocol_version: u16,
    pub schema_version: u16,
    pub transcript_hash: [u8; 32],
    pub key_confirmation: [u8; 32],
    pub signature: Vec<u8>,
}

/// Dual-endpoint attestation that one rooted PQ channel completed and
/// protected an exact higher-level evidence commitment.
///
/// The three handshake messages remain present so an offline verifier can
/// recheck ML-DSA identities, ML-KEM sizes, transcript binding, and the
/// initiator's signed key confirmation. Both enrolled endpoints additionally
/// sign the complete transcript plus `protected_payload_hash`; this makes the
/// completion assertion transferable without disclosing traffic secrets.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, Serialize, Deserialize)]
pub struct PqChannelCompletionEvidenceV1 {
    pub protocol_version: u16,
    pub schema_version: u16,
    pub profile: Vec<u8>,
    pub client_hello: PqChannelClientHelloV1,
    pub server_hello: PqChannelServerHelloV1,
    pub client_finish: PqChannelClientFinishV1,
    pub protected_payload_hash: [u8; 32],
    pub initiator_attestation_signature: Vec<u8>,
    pub responder_attestation_signature: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode, Serialize, Deserialize)]
pub enum PqChannelDirectionV1 {
    InitiatorToResponder,
    ResponderToInitiator,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode, Serialize, Deserialize)]
pub enum PqChannelContentTypeV1 {
    ConsensusVote,
    QuorumCertificate,
    ViewChange,
    FallbackControl,
    AsynchronousConsensus,
    ChannelControl,
}

/// One canonical AEAD-protected application record.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, Serialize, Deserialize)]
pub struct PqChannelRecordV1 {
    pub protocol_version: u16,
    pub schema_version: u16,
    pub transcript_hash: [u8; 32],
    pub direction: PqChannelDirectionV1,
    pub sequence: u64,
    pub content_type: PqChannelContentTypeV1,
    pub plaintext_len: u32,
    pub ciphertext: Vec<u8>,
}

pub struct PqChannelRecordSealer {
    transcript_hash: [u8; 32],
    direction: PqChannelDirectionV1,
    next_sequence: u64,
    key: [u8; 32],
}

pub struct PqChannelRecordOpener {
    transcript_hash: [u8; 32],
    direction: PqChannelDirectionV1,
    next_sequence: u64,
    key: [u8; 32],
}

impl Drop for PqChannelRecordSealer {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl Drop for PqChannelRecordOpener {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

fn record_nonce(sequence: u64) -> dcrypt::algorithms::types::Nonce<12> {
    let mut nonce = [0; 12];
    nonce[4..].copy_from_slice(&sequence.to_be_bytes());
    dcrypt::algorithms::types::Nonce::new(nonce)
}

fn record_aad(record: &PqChannelRecordV1) -> Result<Vec<u8>> {
    canonical_bytes(&(
        RECORD_AAD_DOMAIN.to_vec(),
        record.protocol_version,
        record.schema_version,
        record.transcript_hash,
        record.direction,
        record.sequence,
        record.content_type,
        record.plaintext_len,
    ))
}

impl PqChannelRecordSealer {
    pub fn new(transcript_hash: [u8; 32], direction: PqChannelDirectionV1, key: &[u8; 32]) -> Self {
        Self {
            transcript_hash,
            direction,
            next_sequence: 0,
            key: *key,
        }
    }

    pub fn seal(
        &mut self,
        content_type: PqChannelContentTypeV1,
        plaintext: &[u8],
    ) -> Result<PqChannelRecordV1> {
        if plaintext.len() > MAX_RECORD_PLAINTEXT {
            return Err(anyhow!("PQ channel record exceeds the plaintext limit"));
        }
        if self.next_sequence == u64::MAX {
            return Err(anyhow!(
                "PQ channel send sequence exhausted; rekey required"
            ));
        }
        let plaintext_len = u32::try_from(plaintext.len())
            .map_err(|_| anyhow!("PQ channel plaintext length does not fit u32"))?;
        let mut record = PqChannelRecordV1 {
            protocol_version: AFT_PQ_CHANNEL_PROTOCOL_VERSION,
            schema_version: AFT_PQ_CHANNEL_SCHEMA_VERSION,
            transcript_hash: self.transcript_hash,
            direction: self.direction,
            sequence: self.next_sequence,
            content_type,
            plaintext_len,
            ciphertext: Vec::new(),
        };
        let nonce = record_nonce(record.sequence);
        let aad = record_aad(&record)?;
        let cipher = ChaCha20Poly1305::new(&self.key);
        record.ciphertext = SymmetricCipher::encrypt(&cipher)
            .with_nonce(&nonce)
            .with_aad(&aad)
            .encrypt(plaintext)?
            .as_ref()
            .to_vec();
        self.next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or_else(|| anyhow!("PQ channel send sequence overflow"))?;
        Ok(record)
    }
}

impl PqChannelRecordOpener {
    pub fn new(transcript_hash: [u8; 32], direction: PqChannelDirectionV1, key: &[u8; 32]) -> Self {
        Self {
            transcript_hash,
            direction,
            next_sequence: 0,
            key: *key,
        }
    }

    pub fn open(&mut self, record: &PqChannelRecordV1) -> Result<Vec<u8>> {
        validate_versions(record.protocol_version, record.schema_version)?;
        if record.transcript_hash != self.transcript_hash || record.direction != self.direction {
            return Err(anyhow!(
                "PQ channel record belongs to another session or direction"
            ));
        }
        if record.sequence != self.next_sequence {
            return Err(anyhow!(
                "PQ channel record sequence mismatch: expected {}, got {}",
                self.next_sequence,
                record.sequence
            ));
        }
        let plaintext_len = usize::try_from(record.plaintext_len)
            .map_err(|_| anyhow!("PQ channel plaintext length is invalid"))?;
        if plaintext_len > MAX_RECORD_PLAINTEXT
            || record.ciphertext.len() != plaintext_len.saturating_add(16)
        {
            return Err(anyhow!("PQ channel record length is invalid"));
        }
        let nonce = record_nonce(record.sequence);
        let aad = record_aad(record)?;
        let ciphertext = dcrypt::api::types::Ciphertext::new(record.ciphertext.clone());
        let cipher = ChaCha20Poly1305::new(&self.key);
        let plaintext = SymmetricCipher::decrypt(&cipher)
            .with_nonce(&nonce)
            .with_aad(&aad)
            .decrypt(&ciphertext)
            .map_err(|_| anyhow!("PQ channel record authentication failed"))?;
        if plaintext.len() != plaintext_len {
            return Err(anyhow!("PQ channel decrypted length mismatch"));
        }
        self.next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or_else(|| anyhow!("PQ channel receive sequence overflow"))?;
        Ok(plaintext)
    }
}

pub struct PqChannelInitiatorState {
    scope: PqChannelScopeV1,
    expected_responder_key_hash: [u8; 32],
    identity: MldsaKeyPair,
    kem_private_key: HybridPrivateKey,
    hello: PqChannelClientHelloV1,
}

pub struct PqChannelResponderState {
    scope: PqChannelScopeV1,
    initiator_public_key: MldsaPublicKey,
    hello: PqChannelClientHelloV1,
    server_hello: PqChannelServerHelloV1,
    shared_secret: zeroize::Zeroizing<Vec<u8>>,
}

impl PqChannelInitiatorState {
    /// Checks whether a response belongs to this in-flight transcript without
    /// consuming the ephemeral decapsulation state. Callers use this to reject
    /// delayed responses from an earlier carrier connection safely.
    pub fn accepts_server_hello(&self, server_hello: &PqChannelServerHelloV1) -> Result<bool> {
        Ok(server_hello.client_hello_hash == hash_encoded(&self.hello)?)
    }
}

impl PqChannelResponderState {
    /// Returns the already authenticated response for an exact retransmission
    /// of the client hello. This makes carrier-level request retries
    /// idempotent without performing a second KEM encapsulation.
    pub fn response_for_retry(
        &self,
        hello: &PqChannelClientHelloV1,
    ) -> Option<PqChannelServerHelloV1> {
        (&self.hello == hello).then(|| self.server_hello.clone())
    }

    /// Returns the authenticated client hello retained by this responder. The
    /// session owner keeps it after completion solely as a replay guard, so a
    /// delayed copy cannot replace the established traffic keys.
    pub fn client_hello_for_replay_guard(&self) -> &PqChannelClientHelloV1 {
        &self.hello
    }

    /// Checks whether a finish belongs to this in-flight transcript without
    /// consuming the responder's shared secret.
    pub fn accepts_finish(&self, finish: &PqChannelClientFinishV1) -> Result<bool> {
        Ok(finish.transcript_hash == transcript_hash(&self.hello, &self.server_hello)?)
    }
}

/// Directional traffic secrets. The arrays are erased when this object drops.
pub struct PqChannelTrafficKeys {
    transcript_hash: [u8; 32],
    initiator_to_responder: [u8; 32],
    responder_to_initiator: [u8; 32],
}

impl PqChannelTrafficKeys {
    pub fn transcript_hash(&self) -> [u8; 32] {
        self.transcript_hash
    }

    pub fn initiator_to_responder(&self) -> &[u8; 32] {
        &self.initiator_to_responder
    }

    pub fn responder_to_initiator(&self) -> &[u8; 32] {
        &self.responder_to_initiator
    }
}

impl Drop for PqChannelTrafficKeys {
    fn drop(&mut self) {
        self.initiator_to_responder.zeroize();
        self.responder_to_initiator.zeroize();
    }
}

fn random_nonce() -> [u8; 32] {
    let mut nonce = [0; 32];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    nonce
}

fn canonical_bytes<T: Encode>(value: &T) -> Result<Vec<u8>> {
    codec::to_bytes_canonical(value).map_err(anyhow::Error::msg)
}

fn hash_encoded<T: Encode>(value: &T) -> Result<[u8; 32]> {
    sha256(canonical_bytes(value)?).map_err(|error| anyhow!(error.to_string()))
}

fn ml_dsa_key_hash(public_key: &[u8]) -> Result<[u8; 32]> {
    if public_key.len() != 1312 {
        return Err(anyhow!(
            "ML-DSA-44 public key must be 1312 bytes, got {}",
            public_key.len()
        ));
    }
    account_id_from_key_material(SignatureSuite::ML_DSA_44, public_key)
        .map_err(|error| anyhow!(error.to_string()))
}

fn verify_ml_dsa(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<MldsaPublicKey> {
    if public_key.len() != 1312 {
        return Err(anyhow!("invalid ML-DSA-44 public key length"));
    }
    let public_key = MldsaPublicKey::from_bytes(public_key)?;
    let signature = MldsaSignature::from_bytes(signature)?;
    public_key
        .verify(message, &signature)
        .map_err(|_| anyhow!("ML-DSA-44 channel signature is invalid"))?;
    Ok(public_key)
}

fn client_hello_signing_bytes(hello: &PqChannelClientHelloV1) -> Result<Vec<u8>> {
    let mut unsigned = hello.clone();
    unsigned.signature.clear();
    canonical_bytes(&(CLIENT_HELLO_DOMAIN.to_vec(), unsigned))
}

fn server_hello_signing_bytes(server: &PqChannelServerHelloV1) -> Result<Vec<u8>> {
    let mut unsigned = server.clone();
    unsigned.signature.clear();
    canonical_bytes(&(SERVER_HELLO_DOMAIN.to_vec(), unsigned))
}

fn transcript_hash(
    hello: &PqChannelClientHelloV1,
    server: &PqChannelServerHelloV1,
) -> Result<[u8; 32]> {
    hash_encoded(&(AFT_PQ_CHANNEL_PROFILE.to_vec(), hello, server))
}

fn hmac(key: &[u8], input: &[u8]) -> Result<[u8; 32]> {
    let output = Hmac::<Sha256>::mac(key, input)?;
    output
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("HMAC-SHA-256 returned a non-32-byte output"))
}

fn derive_traffic_keys(
    shared_secret: &[u8],
    transcript_hash: [u8; 32],
) -> Result<(PqChannelTrafficKeys, [u8; 32])> {
    let mut extract_input = Vec::with_capacity(KDF_EXTRACT_DOMAIN.len() + 32);
    extract_input.extend_from_slice(KDF_EXTRACT_DOMAIN);
    extract_input.extend_from_slice(&transcript_hash);
    let mut prk = hmac(shared_secret, &extract_input)?;

    let expand = |label: &[u8]| -> Result<[u8; 32]> {
        let mut input = Vec::with_capacity(KDF_EXPAND_DOMAIN.len() + label.len() + 32);
        input.extend_from_slice(KDF_EXPAND_DOMAIN);
        input.extend_from_slice(label);
        input.extend_from_slice(&transcript_hash);
        hmac(&prk, &input)
    };
    let initiator_to_responder = expand(b"initiator-to-responder")?;
    let responder_to_initiator = expand(b"responder-to-initiator")?;
    let confirmation = expand(b"client-key-confirmation")?;
    prk.zeroize();
    Ok((
        PqChannelTrafficKeys {
            transcript_hash,
            initiator_to_responder,
            responder_to_initiator,
        },
        confirmation,
    ))
}

fn validate_versions(protocol_version: u16, schema_version: u16) -> Result<()> {
    if protocol_version != AFT_PQ_CHANNEL_PROTOCOL_VERSION
        || schema_version != AFT_PQ_CHANNEL_SCHEMA_VERSION
    {
        return Err(anyhow!(
            "unsupported PQ channel protocol/schema version {protocol_version}/{schema_version}"
        ));
    }
    Ok(())
}

/// Starts an initiator handshake. Authority for `identity` is checked again by
/// the responder against `expected_initiator_key_hash`.
pub fn start_pq_channel(
    scope: PqChannelScopeV1,
    identity: &MldsaKeyPair,
    expected_responder_key_hash: [u8; 32],
) -> Result<(PqChannelInitiatorState, PqChannelClientHelloV1)> {
    scope.validate()?;
    let kem = HybridKEM::new(SecurityLevel::Level3)?;
    let kem_keypair = kem.generate_keypair()?;
    let identity_public_key = identity.public_key().to_bytes();
    ml_dsa_key_hash(&identity_public_key)?;
    let mut hello = PqChannelClientHelloV1 {
        protocol_version: AFT_PQ_CHANNEL_PROTOCOL_VERSION,
        schema_version: AFT_PQ_CHANNEL_SCHEMA_VERSION,
        scope: scope.clone(),
        nonce: random_nonce(),
        kem_public_key: kem_keypair.public_key.to_bytes(),
        identity_suite: SignatureSuite::ML_DSA_44,
        identity_public_key,
        signature: Vec::new(),
    };
    hello.signature = identity
        .sign(&client_hello_signing_bytes(&hello)?)?
        .to_bytes();
    let state = PqChannelInitiatorState {
        scope,
        expected_responder_key_hash,
        identity: identity.clone(),
        kem_private_key: kem_keypair.private_key,
        hello: hello.clone(),
    };
    Ok((state, hello))
}

/// Verifies the enrolled initiator, encapsulates to its ephemeral ML-KEM key,
/// and returns the responder's authenticated transcript contribution.
pub fn accept_pq_channel(
    expected_scope: &PqChannelScopeV1,
    expected_initiator_key_hash: [u8; 32],
    expected_responder_key_hash: [u8; 32],
    responder_identity: &MldsaKeyPair,
    hello: PqChannelClientHelloV1,
) -> Result<(PqChannelResponderState, PqChannelServerHelloV1)> {
    expected_scope.validate()?;
    validate_versions(hello.protocol_version, hello.schema_version)?;
    if &hello.scope != expected_scope {
        return Err(anyhow!("PQ channel client hello scope mismatch"));
    }
    if hello.identity_suite != SignatureSuite::ML_DSA_44 {
        return Err(anyhow!("PQ channel client used a non-ML-DSA-44 identity"));
    }
    if ml_dsa_key_hash(&hello.identity_public_key)? != expected_initiator_key_hash {
        return Err(anyhow!("PQ channel initiator key is not enrolled"));
    }
    let initiator_public_key = verify_ml_dsa(
        &hello.identity_public_key,
        &client_hello_signing_bytes(&hello)?,
        &hello.signature,
    )?;

    let responder_public_key = responder_identity.public_key().to_bytes();
    if ml_dsa_key_hash(&responder_public_key)? != expected_responder_key_hash {
        return Err(anyhow!("PQ channel responder key is not enrolled"));
    }
    let kem = HybridKEM::new(SecurityLevel::Level3)?;
    let initiator_kem_public =
        crate::kem::hybrid::HybridPublicKey::from_bytes(&hello.kem_public_key)?;
    if hello.kem_public_key.len() != 1217 {
        return Err(anyhow!("PQ channel requires the level-3 hybrid ML-KEM key"));
    }
    let encapsulated = kem.encapsulate(&initiator_kem_public)?;
    let shared_secret = zeroize::Zeroizing::new(encapsulated.shared_secret().to_vec());
    let mut server_hello = PqChannelServerHelloV1 {
        protocol_version: AFT_PQ_CHANNEL_PROTOCOL_VERSION,
        schema_version: AFT_PQ_CHANNEL_SCHEMA_VERSION,
        client_hello_hash: hash_encoded(&hello)?,
        nonce: random_nonce(),
        kem_ciphertext: encapsulated.to_bytes(),
        identity_suite: SignatureSuite::ML_DSA_44,
        identity_public_key: responder_public_key,
        signature: Vec::new(),
    };
    server_hello.signature = responder_identity
        .sign(&server_hello_signing_bytes(&server_hello)?)?
        .to_bytes();
    Ok((
        PqChannelResponderState {
            scope: expected_scope.clone(),
            initiator_public_key,
            hello,
            server_hello: server_hello.clone(),
            shared_secret,
        },
        server_hello,
    ))
}

/// Verifies the enrolled responder, decapsulates the KEM ciphertext and emits
/// signed key confirmation. No application data is authorized before this.
pub fn finish_pq_channel(
    state: PqChannelInitiatorState,
    server_hello: PqChannelServerHelloV1,
) -> Result<(PqChannelClientFinishV1, PqChannelTrafficKeys)> {
    validate_versions(server_hello.protocol_version, server_hello.schema_version)?;
    if server_hello.client_hello_hash != hash_encoded(&state.hello)? {
        return Err(anyhow!(
            "PQ channel server hello binds another client hello"
        ));
    }
    if server_hello.identity_suite != SignatureSuite::ML_DSA_44
        || ml_dsa_key_hash(&server_hello.identity_public_key)? != state.expected_responder_key_hash
    {
        return Err(anyhow!("PQ channel responder key is not enrolled"));
    }
    verify_ml_dsa(
        &server_hello.identity_public_key,
        &server_hello_signing_bytes(&server_hello)?,
        &server_hello.signature,
    )?;
    if server_hello.kem_ciphertext.len() != 1121 {
        return Err(anyhow!(
            "PQ channel requires the level-3 hybrid ML-KEM ciphertext"
        ));
    }
    let kem = HybridKEM::new(SecurityLevel::Level3)?;
    let encapsulated = HybridEncapsulated::from_bytes(&server_hello.kem_ciphertext)?;
    let shared_secret = kem.decapsulate(&state.kem_private_key, &encapsulated)?;
    let transcript_hash = transcript_hash(&state.hello, &server_hello)?;
    let (traffic_keys, confirmation_key) =
        derive_traffic_keys(shared_secret.as_slice(), transcript_hash)?;
    let key_confirmation = hmac(&confirmation_key, &transcript_hash)?;
    let mut finish = PqChannelClientFinishV1 {
        protocol_version: AFT_PQ_CHANNEL_PROTOCOL_VERSION,
        schema_version: AFT_PQ_CHANNEL_SCHEMA_VERSION,
        transcript_hash,
        key_confirmation,
        signature: Vec::new(),
    };
    finish.signature = state
        .identity
        .sign(&canonical_bytes(&(CLIENT_FINISH_DOMAIN.to_vec(), &finish))?)?
        .to_bytes();
    // The scope is retained in initiator state so consuming the state cannot
    // accidentally complete a response for a different pair.
    state.scope.validate()?;
    Ok((finish, traffic_keys))
}

/// Completes responder-side mutual authentication and key confirmation.
pub fn complete_pq_channel(
    state: PqChannelResponderState,
    finish: PqChannelClientFinishV1,
) -> Result<PqChannelTrafficKeys> {
    validate_versions(finish.protocol_version, finish.schema_version)?;
    let transcript_hash = transcript_hash(&state.hello, &state.server_hello)?;
    if finish.transcript_hash != transcript_hash {
        return Err(anyhow!("PQ channel finish transcript mismatch"));
    }
    let mut unsigned_finish = finish.clone();
    unsigned_finish.signature.clear();
    state.initiator_public_key.verify(
        &canonical_bytes(&(CLIENT_FINISH_DOMAIN.to_vec(), &unsigned_finish))?,
        &MldsaSignature::from_bytes(&finish.signature)?,
    )?;
    let (traffic_keys, confirmation_key) =
        derive_traffic_keys(state.shared_secret.as_slice(), transcript_hash)?;
    let expected_confirmation = hmac(&confirmation_key, &transcript_hash)?;
    if subtle::ConstantTimeEq::ct_eq(
        expected_confirmation.as_slice(),
        finish.key_confirmation.as_slice(),
    )
    .unwrap_u8()
        != 1
    {
        return Err(anyhow!("PQ channel key confirmation failed"));
    }
    state.scope.validate()?;
    Ok(traffic_keys)
}

fn completion_evidence_signing_bytes(evidence: &PqChannelCompletionEvidenceV1) -> Result<Vec<u8>> {
    let mut unsigned = evidence.clone();
    unsigned.initiator_attestation_signature.clear();
    unsigned.responder_attestation_signature.clear();
    canonical_bytes(&(COMPLETION_EVIDENCE_DOMAIN.to_vec(), unsigned))
}

/// Create a transferable completion attestation after both endpoints derived
/// the same transcript-bound traffic keys. The protected payload is represented
/// only by its higher-level commitment; traffic keys and plaintext stay secret.
pub fn attest_pq_channel_completion(
    client_hello: PqChannelClientHelloV1,
    server_hello: PqChannelServerHelloV1,
    client_finish: PqChannelClientFinishV1,
    initiator_keys: &PqChannelTrafficKeys,
    responder_keys: &PqChannelTrafficKeys,
    initiator_identity: &MldsaKeyPair,
    responder_identity: &MldsaKeyPair,
    protected_payload_hash: [u8; 32],
) -> Result<PqChannelCompletionEvidenceV1> {
    if protected_payload_hash == [0; 32] {
        return Err(anyhow!(
            "PQ channel completion evidence protects an empty hash"
        ));
    }
    let expected_transcript = transcript_hash(&client_hello, &server_hello)?;
    if initiator_keys.transcript_hash() != expected_transcript
        || responder_keys.transcript_hash() != expected_transcript
        || client_finish.transcript_hash != expected_transcript
        || initiator_identity.public_key().to_bytes() != client_hello.identity_public_key
        || responder_identity.public_key().to_bytes() != server_hello.identity_public_key
    {
        return Err(anyhow!(
            "PQ channel completion attestation does not match the completed session"
        ));
    }
    let mut evidence = PqChannelCompletionEvidenceV1 {
        protocol_version: AFT_PQ_CHANNEL_PROTOCOL_VERSION,
        schema_version: AFT_PQ_CHANNEL_SCHEMA_VERSION,
        profile: AFT_PQ_CHANNEL_PROFILE.to_vec(),
        client_hello,
        server_hello,
        client_finish,
        protected_payload_hash,
        initiator_attestation_signature: Vec::new(),
        responder_attestation_signature: Vec::new(),
    };
    let message = completion_evidence_signing_bytes(&evidence)?;
    evidence.initiator_attestation_signature = initiator_identity.sign(&message)?.to_bytes();
    evidence.responder_attestation_signature = responder_identity.sign(&message)?.to_bytes();
    verify_pq_channel_completion_evidence(&evidence)?;
    Ok(evidence)
}

/// Offline verification of one dual-endpoint completion attestation.
///
/// The M8 portable profile requires endpoint account IDs to be derived from
/// the exact enrolled ML-DSA keys in this transcript. Deployments that use a
/// distinct channel-key hierarchy need a separately authenticated enrollment
/// proof and do not satisfy this verifier by assertion alone.
pub fn verify_pq_channel_completion_evidence(
    evidence: &PqChannelCompletionEvidenceV1,
) -> Result<[u8; 32]> {
    validate_versions(evidence.protocol_version, evidence.schema_version)?;
    validate_versions(
        evidence.client_hello.protocol_version,
        evidence.client_hello.schema_version,
    )?;
    validate_versions(
        evidence.server_hello.protocol_version,
        evidence.server_hello.schema_version,
    )?;
    validate_versions(
        evidence.client_finish.protocol_version,
        evidence.client_finish.schema_version,
    )?;
    if evidence.profile != AFT_PQ_CHANNEL_PROFILE || evidence.protected_payload_hash == [0; 32] {
        return Err(anyhow!(
            "unsupported or incomplete PQ channel completion evidence"
        ));
    }
    evidence.client_hello.scope.validate()?;
    if evidence.client_hello.identity_suite != SignatureSuite::ML_DSA_44
        || evidence.server_hello.identity_suite != SignatureSuite::ML_DSA_44
        || evidence.client_hello.kem_public_key.len() != 1217
        || evidence.server_hello.kem_ciphertext.len() != 1121
    {
        return Err(anyhow!(
            "PQ channel completion evidence uses a non-PQ suite"
        ));
    }
    if ml_dsa_key_hash(&evidence.client_hello.identity_public_key)?
        != evidence.client_hello.scope.initiator.0
        || ml_dsa_key_hash(&evidence.server_hello.identity_public_key)?
            != evidence.client_hello.scope.responder.0
    {
        return Err(anyhow!(
            "PQ channel completion keys are not the rooted endpoint identities"
        ));
    }
    let initiator = verify_ml_dsa(
        &evidence.client_hello.identity_public_key,
        &client_hello_signing_bytes(&evidence.client_hello)?,
        &evidence.client_hello.signature,
    )?;
    if evidence.server_hello.client_hello_hash != hash_encoded(&evidence.client_hello)? {
        return Err(anyhow!(
            "PQ channel server hello binds another client hello"
        ));
    }
    let responder = verify_ml_dsa(
        &evidence.server_hello.identity_public_key,
        &server_hello_signing_bytes(&evidence.server_hello)?,
        &evidence.server_hello.signature,
    )?;
    let expected_transcript = transcript_hash(&evidence.client_hello, &evidence.server_hello)?;
    if evidence.client_finish.transcript_hash != expected_transcript {
        return Err(anyhow!("PQ channel finish transcript mismatch"));
    }
    let mut unsigned_finish = evidence.client_finish.clone();
    unsigned_finish.signature.clear();
    initiator.verify(
        &canonical_bytes(&(CLIENT_FINISH_DOMAIN.to_vec(), &unsigned_finish))?,
        &MldsaSignature::from_bytes(&evidence.client_finish.signature)?,
    )?;
    let message = completion_evidence_signing_bytes(evidence)?;
    initiator.verify(
        &message,
        &MldsaSignature::from_bytes(&evidence.initiator_attestation_signature)?,
    )?;
    responder.verify(
        &message,
        &MldsaSignature::from_bytes(&evidence.responder_attestation_signature)?,
    )?;
    hash_encoded(&(COMPLETION_EVIDENCE_DOMAIN.to_vec(), evidence))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sign::dilithium::MldsaScheme;

    fn identities() -> (MldsaKeyPair, MldsaKeyPair) {
        let scheme = MldsaScheme::new(SecurityLevel::Level2);
        (
            scheme.generate_keypair().unwrap(),
            scheme.generate_keypair().unwrap(),
        )
    }

    fn scope() -> PqChannelScopeV1 {
        PqChannelScopeV1 {
            network_id: [1; 32],
            configuration_hash: [2; 32],
            epoch: 9,
            initiator: AccountId([3; 32]),
            responder: AccountId([4; 32]),
            initiator_transport_binding: [5; 32],
            responder_transport_binding: [6; 32],
        }
    }

    fn key_hash(keypair: &MldsaKeyPair) -> [u8; 32] {
        ml_dsa_key_hash(&keypair.public_key().to_bytes()).unwrap()
    }

    #[test]
    fn mutual_handshake_derives_complementary_transcript_bound_keys() {
        let (initiator, responder) = identities();
        let scope = scope();
        let (initiator_state, hello) =
            start_pq_channel(scope.clone(), &initiator, key_hash(&responder)).unwrap();
        let (responder_state, server) = accept_pq_channel(
            &scope,
            key_hash(&initiator),
            key_hash(&responder),
            &responder,
            hello,
        )
        .unwrap();
        let (finish, initiator_keys) = finish_pq_channel(initiator_state, server).unwrap();
        let responder_keys = complete_pq_channel(responder_state, finish).unwrap();

        assert_eq!(
            initiator_keys.transcript_hash(),
            responder_keys.transcript_hash()
        );
        assert_eq!(
            initiator_keys.initiator_to_responder(),
            responder_keys.initiator_to_responder()
        );
        assert_eq!(
            initiator_keys.responder_to_initiator(),
            responder_keys.responder_to_initiator()
        );
        assert_ne!(
            initiator_keys.initiator_to_responder(),
            initiator_keys.responder_to_initiator()
        );
    }

    #[test]
    fn cross_configuration_replay_and_unenrolled_keys_fail_closed() {
        let (initiator, responder) = identities();
        let scope = scope();
        let (_, hello) = start_pq_channel(scope.clone(), &initiator, key_hash(&responder)).unwrap();

        let mut other_scope = scope.clone();
        other_scope.configuration_hash[0] ^= 1;
        assert!(accept_pq_channel(
            &other_scope,
            key_hash(&initiator),
            key_hash(&responder),
            &responder,
            hello.clone(),
        )
        .is_err());
        assert!(
            accept_pq_channel(&scope, [0x55; 32], key_hash(&responder), &responder, hello,)
                .is_err()
        );
    }

    #[test]
    fn transcript_and_key_confirmation_mutations_fail_closed() {
        let (initiator, responder) = identities();
        let scope = scope();
        let (initiator_state, hello) =
            start_pq_channel(scope.clone(), &initiator, key_hash(&responder)).unwrap();
        let (responder_state, server) = accept_pq_channel(
            &scope,
            key_hash(&initiator),
            key_hash(&responder),
            &responder,
            hello,
        )
        .unwrap();
        let (mut finish, _) = finish_pq_channel(initiator_state, server).unwrap();
        finish.key_confirmation[0] ^= 1;
        assert!(complete_pq_channel(responder_state, finish).is_err());
    }

    #[test]
    fn server_ciphertext_and_signature_mutations_fail_closed() {
        let (initiator, responder) = identities();
        let scope = scope();
        let (initiator_state, hello) =
            start_pq_channel(scope.clone(), &initiator, key_hash(&responder)).unwrap();
        let (_, mut server) = accept_pq_channel(
            &scope,
            key_hash(&initiator),
            key_hash(&responder),
            &responder,
            hello,
        )
        .unwrap();
        server.kem_ciphertext[0] ^= 1;
        assert!(finish_pq_channel(initiator_state, server).is_err());
    }

    #[test]
    fn records_are_confidential_transcript_bound_and_replay_ordered() {
        let (initiator, responder) = identities();
        let scope = scope();
        let (initiator_state, hello) =
            start_pq_channel(scope.clone(), &initiator, key_hash(&responder)).unwrap();
        let (responder_state, server) = accept_pq_channel(
            &scope,
            key_hash(&initiator),
            key_hash(&responder),
            &responder,
            hello,
        )
        .unwrap();
        let (finish, initiator_keys) = finish_pq_channel(initiator_state, server).unwrap();
        let responder_keys = complete_pq_channel(responder_state, finish).unwrap();

        let mut sealer = PqChannelRecordSealer::new(
            initiator_keys.transcript_hash(),
            PqChannelDirectionV1::InitiatorToResponder,
            initiator_keys.initiator_to_responder(),
        );
        let mut opener = PqChannelRecordOpener::new(
            responder_keys.transcript_hash(),
            PqChannelDirectionV1::InitiatorToResponder,
            responder_keys.initiator_to_responder(),
        );
        let plaintext = b"private AFT vote bytes";
        let first = sealer
            .seal(PqChannelContentTypeV1::ConsensusVote, plaintext)
            .unwrap();
        assert!(!first
            .ciphertext
            .windows(plaintext.len())
            .any(|w| w == plaintext));
        assert_eq!(opener.open(&first).unwrap(), plaintext);
        assert!(opener.open(&first).is_err());

        let mut second = sealer
            .seal(PqChannelContentTypeV1::QuorumCertificate, b"qc")
            .unwrap();
        second.content_type = PqChannelContentTypeV1::ViewChange;
        assert!(opener.open(&second).is_err());
    }

    #[test]
    fn dual_endpoint_completion_evidence_is_offline_verifiable_and_payload_bound() {
        let (initiator, responder) = identities();
        let mut scope = scope();
        scope.initiator = AccountId(key_hash(&initiator));
        scope.responder = AccountId(key_hash(&responder));
        let (initiator_state, hello) =
            start_pq_channel(scope.clone(), &initiator, key_hash(&responder)).unwrap();
        let (responder_state, server) = accept_pq_channel(
            &scope,
            key_hash(&initiator),
            key_hash(&responder),
            &responder,
            hello.clone(),
        )
        .unwrap();
        let (finish, initiator_keys) = finish_pq_channel(initiator_state, server.clone()).unwrap();
        let responder_keys = complete_pq_channel(responder_state, finish.clone()).unwrap();
        let evidence = attest_pq_channel_completion(
            hello,
            server,
            finish,
            &initiator_keys,
            &responder_keys,
            &initiator,
            &responder,
            [0x44; 32],
        )
        .unwrap();
        verify_pq_channel_completion_evidence(&evidence).unwrap();

        for mutate in 0..3 {
            let mut invalid = evidence.clone();
            match mutate {
                0 => invalid.protected_payload_hash[0] ^= 1,
                1 => invalid.client_hello.scope.configuration_hash[0] ^= 1,
                2 => invalid.responder_attestation_signature[0] ^= 1,
                _ => unreachable!(),
            }
            assert!(verify_pq_channel_completion_evidence(&invalid).is_err());
        }
    }
}
