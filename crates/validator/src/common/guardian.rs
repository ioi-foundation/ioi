// Path: crates/validator/src/common/guardian.rs

//! Implements the Guardian container, the root of trust for the validator,
//! and the GuardianSigner abstraction for Oracle-anchored signing.

use crate::common::{build_key_authority, KeyAuthority, MemoryTransparencyLog, TransparencyLog};
use crate::config::GuardianConfig;
use crate::standard::workload::ipc::create_ipc_server_config;
use anyhow::{anyhow, Result};
use async_trait::async_trait;
// FIX: Import Sha256 and HashFunction directly from dcrypt
use dcrypt::algorithms::hash::{HashFunction, Sha256};
use futures::stream::{FuturesUnordered, StreamExt};
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::client::conn::http1;
use hyper::Request as HttpRequest;
use hyper_util::rt::TokioIo;
use ioi_api::crypto::{SerializableKey, SigningKey, SigningKeyPair, VerifyingKey};
use ioi_api::validator::Container;
use ioi_client::security::SecurityChannel;
use ioi_crypto::key_store::{decrypt_key, encrypt_key};
use ioi_crypto::sign::bls::{BlsPrivateKey, BlsPublicKey, BlsSignature};
use ioi_crypto::sign::guardian_committee::{
    aggregate_member_signatures, canonical_decision_hash, canonical_manifest_hash,
    canonical_witness_manifest_hash, canonical_witness_statement_hash,
};
use ioi_crypto::transport::hybrid_kem_tls::{
    derive_application_key, server_post_handshake, AeadWrappedStream,
};
use ioi_ipc::control::{
    guardian_control_client::GuardianControlClient, GuardianMemberSignature,
    ReportWitnessFaultRequest, SignCommitteeDecisionRequest, SignConsensusRequest,
    SignWitnessStatementRequest,
};
use ioi_ipc::IpcClientType;
use ioi_types::app::{
    account_id_from_key_material, AccountId, BinaryMeasurement, BootAttestation, EgressReceipt,
    GuardianCommitteeManifest, GuardianCommitteeMember, GuardianDecision, GuardianDecisionDomain,
    GuardianLogCheckpoint, GuardianProductionMode, GuardianQuorumCertificate,
    GuardianWitnessCertificate, GuardianWitnessCommitteeManifest, GuardianWitnessFaultEvidence,
    GuardianWitnessStatement, SignatureBundle, SignatureSuite,
};
use ioi_types::codec;
use ioi_types::config::GuardianVerifierPolicyConfig;
use ioi_types::error::ValidatorError;
// [FIX] Added Ia5String and KeyPair for rcgen 0.13 compatibility
use rcgen::{CertificateParams, Ia5String, KeyPair, KeyUsagePurpose, SanType};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs::File;
use std::io::{self, Read, Write};
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex as StdMutex,
};
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::Mutex as TokioMutex;
use tokio_rustls::{
    rustls::{pki_types::ServerName, ClientConfig, RootCertStore, ServerConfig},
    TlsAcceptor, TlsConnector, TlsStream,
};
use tonic::transport::Channel;

// --- Signing Abstraction for Oracle-Anchored Consensus ---

/// Abstract interface for a signing authority.
/// This allows the Orchestrator to use either a local key (for development)
/// or a remote, cryptographically isolated Oracle (for production non-equivocation enforcement).
#[async_trait]
pub trait GuardianSigner: Send + Sync {
    /// Signs a consensus payload (usually a block header hash).
    /// Returns the signature along with the Oracle's counter and trace.
    async fn sign_consensus_payload(
        &self,
        payload_hash: [u8; 32],
        height: u64,
        view: u64,
        experimental_witness_manifest: Option<([u8; 32], u8)>,
    ) -> Result<SignatureBundle>;

    /// Persists experimental witness-fault evidence when the runtime detects witness omission or
    /// reassignment conditions.
    async fn report_witness_fault(&self, _evidence: &GuardianWitnessFaultEvidence) -> Result<()> {
        Ok(())
    }

    /// Returns the public key bytes of the signer.
    fn public_key(&self) -> Vec<u8>;
}

/// Local implementation for development/testing.
/// Mimics the Oracle's interface but uses an in-memory keypair and zeroed metadata.
pub struct LocalSigner {
    /// [FIX] Made public to allow direct access by ProviderController for non-consensus signing.
    pub keypair: ioi_crypto::sign::eddsa::Ed25519KeyPair,
    // [FIX] Added monotonic counter to satisfy Convergent deterministic invariants in tests
    counter: std::sync::atomic::AtomicU64,
}

impl LocalSigner {
    /// Creates a new `LocalSigner` with the given keypair.
    pub fn new(keypair: ioi_crypto::sign::eddsa::Ed25519KeyPair) -> Self {
        Self {
            keypair,
            counter: std::sync::atomic::AtomicU64::new(0),
        }
    }
}

#[async_trait]
impl GuardianSigner for LocalSigner {
    async fn sign_consensus_payload(
        &self,
        payload_hash: [u8; 32],
        _height: u64,
        _view: u64,
        _experimental_witness_manifest: Option<([u8; 32], u8)>,
    ) -> Result<SignatureBundle> {
        // [FIX] Increment counter to simulate Oracle monotonicity
        let counter = self.counter.fetch_add(1, Ordering::SeqCst) + 1;

        // To support Oracle-anchored logic even in dev mode, we must construct the same payload structure:
        // Payload_Hash || Counter || Trace (0)
        // This ensures verification logic in the consensus engine remains consistent.
        let mut sig_input = Vec::new();
        sig_input.extend_from_slice(&payload_hash);
        sig_input.extend_from_slice(&counter.to_be_bytes());
        sig_input.extend_from_slice(&[0u8; 32]); // Trace = 0

        let signature = self.keypair.private_key().sign(&sig_input)?.to_bytes();

        Ok(SignatureBundle {
            signature,
            counter,
            trace_hash: [0u8; 32],
            guardian_certificate: None,
        })
    }

    fn public_key(&self) -> Vec<u8> {
        self.keypair.public_key().to_bytes()
    }
}

/// Remote implementation connecting to the `ioi-signer` Oracle.
pub struct RemoteSigner {
    url: String,
    client: reqwest::Client,
    // Cache public key on startup to avoid async overhead in tight loops
    public_key: Vec<u8>,
}

impl RemoteSigner {
    /// Creates a new `RemoteSigner` that connects to the specified Oracle URL
    /// and uses the provided public key for validation.
    pub fn new(url: String, public_key: Vec<u8>) -> Self {
        Self {
            url,
            client: reqwest::Client::new(),
            public_key,
        }
    }
}

#[async_trait]
impl GuardianSigner for RemoteSigner {
    async fn sign_consensus_payload(
        &self,
        payload_hash: [u8; 32],
        _height: u64,
        _view: u64,
        _experimental_witness_manifest: Option<([u8; 32], u8)>,
    ) -> Result<SignatureBundle> {
        // The Oracle expects the hash as a hex string.
        let resp = self
            .client
            .post(format!("{}/sign", self.url))
            .json(&serde_json::json!({
                "payload_hash": hex::encode(payload_hash)
            }))
            .send()
            .await?
            .json::<serde_json::Value>()
            .await?;

        // Parse response: { signature: "hex", counter: 123, trace_hash: "hex" }
        let sig_hex = resp["signature"]
            .as_str()
            .ok_or(anyhow!("Missing signature in Oracle response"))?;
        let counter = resp["counter"]
            .as_u64()
            .ok_or(anyhow!("Missing counter in Oracle response"))?;
        let trace_hex = resp["trace_hash"]
            .as_str()
            .ok_or(anyhow!("Missing trace_hash in Oracle response"))?;

        let signature = hex::decode(sig_hex)?;
        let trace_hash_vec = hex::decode(trace_hex)?;
        let trace_hash: [u8; 32] = trace_hash_vec
            .try_into()
            .map_err(|_| anyhow!("Invalid trace hash length"))?;

        Ok(SignatureBundle {
            signature,
            counter,
            trace_hash,
            guardian_certificate: None,
        })
    }

    fn public_key(&self) -> Vec<u8> {
        self.public_key.clone()
    }
}

#[derive(Debug, Clone, Default)]
struct GuardianDecisionState {
    counter: u64,
    trace_hash: [u8; 32],
    slot_locks: HashMap<(u64, u64), [u8; 32]>,
    slot_certificates: HashMap<(u64, u64), GuardianQuorumCertificate>,
}

#[derive(Clone)]
struct GuardianCommitteeClient {
    manifest: GuardianCommitteeManifest,
    manifest_hash: [u8; 32],
    signer_keys: Vec<(usize, BlsPrivateKey)>,
    remote_members: Vec<RemoteCommitteeMember>,
}

#[derive(Debug, Clone)]
struct RemoteCommitteeMember {
    endpoint: String,
}

#[derive(Clone)]
struct GuardianWitnessCommitteeClient {
    manifest: GuardianWitnessCommitteeManifest,
    manifest_hash: [u8; 32],
    signer_keys: Vec<(usize, BlsPrivateKey)>,
    remote_members: Vec<RemoteCommitteeMember>,
}

impl GuardianCommitteeClient {
    fn from_config(
        config: &GuardianConfig,
        validator_account_id: AccountId,
    ) -> Result<Option<Self>> {
        if config.committee.members.is_empty() {
            return Ok(None);
        }
        if config.committee.threshold == 0 {
            return Err(anyhow!("guardian committee threshold must be at least 1"));
        }
        if usize::from(config.committee.threshold) > config.committee.members.len() {
            return Err(anyhow!(
                "guardian committee threshold {} exceeds member count {}",
                config.committee.threshold,
                config.committee.members.len()
            ));
        }
        if usize::from(config.committee.threshold) <= config.committee.members.len() / 2 {
            return Err(anyhow!(
                "guardian committee threshold {} must be a strict majority for size {}",
                config.committee.threshold,
                config.committee.members.len()
            ));
        }
        if matches!(config.production_mode, GuardianProductionMode::Production) {
            if config.committee.members.len() % 2 != 0 {
                return Err(anyhow!(
                    "production guardian committees must be even-sized; got {} members",
                    config.committee.members.len()
                ));
            }
            let providers = config
                .committee
                .members
                .iter()
                .filter_map(|member| member.provider.clone())
                .collect::<BTreeSet<_>>();
            let regions = config
                .committee
                .members
                .iter()
                .filter_map(|member| member.region.clone())
                .collect::<BTreeSet<_>>();
            let host_classes = config
                .committee
                .members
                .iter()
                .filter_map(|member| member.host_class.clone())
                .collect::<BTreeSet<_>>();
            let authorities = config
                .committee
                .members
                .iter()
                .filter_map(|member| member.key_authority_kind.map(|kind| format!("{kind:?}")))
                .collect::<BTreeSet<_>>();
            if providers.len() < 2
                || regions.len() < 2
                || host_classes.len() < 2
                || authorities.len() < 2
            {
                return Err(anyhow!(
                    "production guardian committees require at least two distinct providers, regions, host classes, and key authorities"
                ));
            }
        }

        let policy_hash = digest_to_array(
            Sha256::digest(&serde_json::to_vec(&(
                config.production_mode,
                &config.hardening,
                &config.verifier_policy,
                &config.transparency_log,
            ))?)
            .map_err(|e| anyhow!(e))?,
        )?;
        let measurement_profile_root = digest_to_array(
            Sha256::digest(&serde_json::to_vec(&(
                config.approved_orchestrator_hash.clone(),
                config.approved_workload_hash.clone(),
                config.hardening.measured_boot_required,
            ))?)
            .map_err(|e| anyhow!(e))?,
        )?;

        let manifest = GuardianCommitteeManifest {
            validator_account_id,
            epoch: 1,
            threshold: config.committee.threshold,
            members: config
                .committee
                .members
                .iter()
                .map(|member| GuardianCommitteeMember {
                    member_id: member.member_id.clone(),
                    signature_suite: SignatureSuite::BLS12_381,
                    public_key: member.public_key.clone(),
                    endpoint: member.endpoint.clone(),
                    provider: member.provider.clone(),
                    region: member.region.clone(),
                    host_class: member.host_class.clone(),
                    key_authority_kind: member.key_authority_kind,
                })
                .collect(),
            measurement_profile_root,
            policy_hash,
            transparency_log_id: config.committee.transparency_log_id.clone(),
        };

        let mut signer_keys = Vec::new();
        let mut remote_members = Vec::new();
        for (index, member) in config.committee.members.iter().enumerate() {
            if let Some(path) = &member.private_key_path {
                let signing_key = load_bls_private_key(Path::new(path))?;
                signer_keys.push((index, signing_key));
            } else if let Some(endpoint) = &member.endpoint {
                remote_members.push(RemoteCommitteeMember {
                    endpoint: normalize_guardian_endpoint(endpoint),
                });
            }
        }

        if signer_keys.len() + remote_members.len() < usize::from(manifest.threshold) {
            return Err(anyhow!(
                "guardian committee has {} reachable local/remote members but threshold is {}",
                signer_keys.len() + remote_members.len(),
                manifest.threshold
            ));
        }

        Ok(Some(Self {
            manifest_hash: canonical_manifest_hash(&manifest)
                .map_err(|e| anyhow!(e.to_string()))?,
            manifest,
            signer_keys,
            remote_members,
        }))
    }

    fn manifest_hash(&self) -> [u8; 32] {
        self.manifest_hash
    }

    fn default_measurement_root(&self) -> [u8; 32] {
        self.manifest.measurement_profile_root
    }

    fn default_policy_hash(&self) -> [u8; 32] {
        self.manifest.policy_hash
    }

    fn default_subject(&self) -> Vec<u8> {
        self.manifest.validator_account_id.0.to_vec()
    }

    async fn sign_decision(
        &self,
        decision: &GuardianDecision,
        slot: Option<(u64, u64)>,
    ) -> Result<GuardianQuorumCertificate> {
        let decision_hash =
            canonical_decision_hash(decision).map_err(|e| anyhow!(e.to_string()))?;
        let mut member_signatures = BTreeMap::<usize, BlsSignature>::new();

        for (member_index, signing_key) in &self.signer_keys {
            let signature = signing_key
                .sign(&decision_hash)
                .map_err(|e| anyhow!(e.to_string()))?;
            member_signatures.insert(*member_index, signature);
        }

        if member_signatures.len() < usize::from(self.manifest.threshold) {
            let remote_signatures = self
                .collect_remote_signatures(decision, decision_hash, slot)
                .await?;
            for (member_index, signature) in remote_signatures {
                member_signatures.entry(member_index).or_insert(signature);
            }
        }

        if member_signatures.len() < usize::from(self.manifest.threshold) {
            return Err(anyhow!(
                "guardian committee collected {} signatures but threshold is {}",
                member_signatures.len(),
                self.manifest.threshold
            ));
        }

        let member_signatures = member_signatures.into_iter().collect::<Vec<_>>();
        let (signers_bitfield, aggregated_signature) =
            aggregate_member_signatures(&member_signatures, self.manifest.members.len())
                .map_err(|e| anyhow!(e.to_string()))?;

        Ok(GuardianQuorumCertificate {
            manifest_hash: self.manifest_hash,
            epoch: self.manifest.epoch,
            decision_hash,
            counter: decision.counter,
            trace_hash: decision.trace_hash,
            measurement_root: decision.measurement_root,
            signers_bitfield,
            aggregated_signature,
            log_checkpoint: None,
            experimental_witness_certificate: None,
        })
    }

    async fn collect_remote_signatures(
        &self,
        decision: &GuardianDecision,
        decision_hash: [u8; 32],
        slot: Option<(u64, u64)>,
    ) -> Result<Vec<(usize, BlsSignature)>> {
        let decision_bytes =
            codec::to_bytes_canonical(decision).map_err(|e| anyhow!(e.to_string()))?;
        let mut inflight = FuturesUnordered::new();
        for remote_member in &self.remote_members {
            let endpoint = remote_member.endpoint.clone();
            let manifest_hash = self.manifest_hash;
            let decision_bytes = decision_bytes.clone();
            inflight.push(async move {
                let channel = Channel::from_shared(endpoint.clone())?.connect().await?;
                let mut client = GuardianControlClient::new(channel);
                let response = client
                    .sign_committee_decision(SignCommitteeDecisionRequest {
                        decision: decision_bytes,
                        manifest_hash: manifest_hash.to_vec(),
                        height: slot.map(|(height, _)| height).unwrap_or_default(),
                        view: slot.map(|(_, view)| view).unwrap_or_default(),
                    })
                    .await?
                    .into_inner();
                Ok::<_, anyhow::Error>(response)
            });
        }

        let mut collected = Vec::new();
        while let Some(result) = inflight.next().await {
            let response = match result {
                Ok(response) => response,
                Err(error) => {
                    tracing::warn!(
                        target: "guardian",
                        event = "committee_remote_sign_failed",
                        error = %error
                    );
                    continue;
                }
            };
            let manifest_hash: [u8; 32] =
                response.manifest_hash.as_slice().try_into().map_err(|_| {
                    anyhow!("remote committee response returned invalid manifest hash")
                })?;
            if manifest_hash != self.manifest_hash {
                return Err(anyhow!("remote committee response manifest hash mismatch"));
            }
            let returned_decision_hash: [u8; 32] =
                response.decision_hash.as_slice().try_into().map_err(|_| {
                    anyhow!("remote committee response returned invalid decision hash")
                })?;
            if returned_decision_hash != decision_hash {
                return Err(anyhow!("remote committee response decision hash mismatch"));
            }
            for partial_signature in response.partial_signatures {
                collected
                    .push(self.verify_remote_partial_signature(decision_hash, partial_signature)?);
            }
        }

        Ok(collected)
    }

    fn verify_remote_partial_signature(
        &self,
        decision_hash: [u8; 32],
        partial_signature: GuardianMemberSignature,
    ) -> Result<(usize, BlsSignature)> {
        let member_index = usize::try_from(partial_signature.member_index)
            .map_err(|_| anyhow!("remote committee response member index overflow"))?;
        let member = self
            .manifest
            .members
            .get(member_index)
            .ok_or_else(|| anyhow!("remote committee response signer outside manifest"))?;
        let signature = BlsSignature::from_bytes(&partial_signature.signature)
            .map_err(|e| anyhow!(e.to_string()))?;
        let public_key =
            BlsPublicKey::from_bytes(&member.public_key).map_err(|e| anyhow!(e.to_string()))?;
        public_key
            .verify(&decision_hash, &signature)
            .map_err(|e| anyhow!(e.to_string()))?;
        Ok((member_index, signature))
    }
}

impl GuardianWitnessCommitteeClient {
    fn from_configs(config: &GuardianConfig) -> Result<HashMap<[u8; 32], Self>> {
        let mut committees = HashMap::new();
        for witness_config in &config.experimental_witness_committees {
            if witness_config.members.is_empty() {
                continue;
            }
            if witness_config.threshold == 0 {
                return Err(anyhow!(
                    "experimental witness committee '{}' threshold must be at least 1",
                    witness_config.committee_id
                ));
            }
            if usize::from(witness_config.threshold) > witness_config.members.len() {
                return Err(anyhow!(
                    "experimental witness committee '{}' threshold {} exceeds member count {}",
                    witness_config.committee_id,
                    witness_config.threshold,
                    witness_config.members.len()
                ));
            }
            if usize::from(witness_config.threshold) <= witness_config.members.len() / 2 {
                return Err(anyhow!(
                    "experimental witness committee '{}' threshold {} must be a strict majority for size {}",
                    witness_config.committee_id,
                    witness_config.threshold,
                    witness_config.members.len()
                ));
            }
            if matches!(config.production_mode, GuardianProductionMode::Production)
                && witness_config.members.len() % 2 != 0
            {
                return Err(anyhow!(
                    "production witness committees must be even-sized; '{}' has {} members",
                    witness_config.committee_id,
                    witness_config.members.len()
                ));
            }

            let policy_hash = witness_config.policy_hash.unwrap_or(digest_to_array(
                Sha256::digest(&serde_json::to_vec(&(
                    &witness_config.committee_id,
                    witness_config.epoch,
                    witness_config.threshold,
                    &config.verifier_policy,
                    &config.transparency_log,
                ))?)
                .map_err(|e| anyhow!(e))?,
            )?);
            let manifest = GuardianWitnessCommitteeManifest {
                committee_id: witness_config.committee_id.clone(),
                epoch: witness_config.epoch,
                threshold: witness_config.threshold,
                members: witness_config
                    .members
                    .iter()
                    .map(|member| GuardianCommitteeMember {
                        member_id: member.member_id.clone(),
                        signature_suite: SignatureSuite::BLS12_381,
                        public_key: member.public_key.clone(),
                        endpoint: member.endpoint.clone(),
                        provider: member.provider.clone(),
                        region: member.region.clone(),
                        host_class: member.host_class.clone(),
                        key_authority_kind: member.key_authority_kind,
                    })
                    .collect(),
                policy_hash,
                transparency_log_id: witness_config.transparency_log_id.clone(),
            };

            let mut signer_keys = Vec::new();
            let mut remote_members = Vec::new();
            for (index, member) in witness_config.members.iter().enumerate() {
                if let Some(path) = &member.private_key_path {
                    signer_keys.push((index, load_bls_private_key(Path::new(path))?));
                } else if let Some(endpoint) = &member.endpoint {
                    remote_members.push(RemoteCommitteeMember {
                        endpoint: normalize_guardian_endpoint(endpoint),
                    });
                }
            }

            if signer_keys.len() + remote_members.len() < usize::from(manifest.threshold) {
                return Err(anyhow!(
                    "experimental witness committee '{}' has {} reachable local/remote members but threshold is {}",
                    manifest.committee_id,
                    signer_keys.len() + remote_members.len(),
                    manifest.threshold
                ));
            }

            let manifest_hash =
                canonical_witness_manifest_hash(&manifest).map_err(|e| anyhow!(e.to_string()))?;
            committees.insert(
                manifest_hash,
                Self {
                    manifest,
                    manifest_hash,
                    signer_keys,
                    remote_members,
                },
            );
        }
        Ok(committees)
    }

    async fn sign_witness_statement(
        &self,
        statement: &GuardianWitnessStatement,
        reassignment_depth: u8,
    ) -> Result<GuardianWitnessCertificate> {
        let statement_hash =
            canonical_witness_statement_hash(statement).map_err(|e| anyhow!(e.to_string()))?;
        let mut member_signatures = BTreeMap::<usize, BlsSignature>::new();

        for (member_index, signing_key) in &self.signer_keys {
            let signature = signing_key
                .sign(&statement_hash)
                .map_err(|e| anyhow!(e.to_string()))?;
            member_signatures.insert(*member_index, signature);
        }

        if member_signatures.len() < usize::from(self.manifest.threshold) {
            let remote_signatures = self
                .collect_remote_signatures(statement, statement_hash)
                .await?;
            for (member_index, signature) in remote_signatures {
                member_signatures.entry(member_index).or_insert(signature);
            }
        }

        if member_signatures.len() < usize::from(self.manifest.threshold) {
            return Err(anyhow!(
                "experimental witness committee '{}' collected {} signatures but threshold is {}",
                self.manifest.committee_id,
                member_signatures.len(),
                self.manifest.threshold
            ));
        }

        let member_signatures = member_signatures.into_iter().collect::<Vec<_>>();
        let (signers_bitfield, aggregated_signature) =
            aggregate_member_signatures(&member_signatures, self.manifest.members.len())
                .map_err(|e| anyhow!(e.to_string()))?;

        Ok(GuardianWitnessCertificate {
            manifest_hash: self.manifest_hash,
            epoch: self.manifest.epoch,
            statement_hash,
            signers_bitfield,
            aggregated_signature,
            reassignment_depth,
            log_checkpoint: None,
        })
    }

    async fn collect_remote_signatures(
        &self,
        statement: &GuardianWitnessStatement,
        statement_hash: [u8; 32],
    ) -> Result<Vec<(usize, BlsSignature)>> {
        let statement_bytes =
            codec::to_bytes_canonical(statement).map_err(|e| anyhow!(e.to_string()))?;
        let mut inflight = FuturesUnordered::new();
        for remote_member in &self.remote_members {
            let endpoint = remote_member.endpoint.clone();
            let manifest_hash = self.manifest_hash;
            let statement_bytes = statement_bytes.clone();
            inflight.push(async move {
                let channel = Channel::from_shared(endpoint.clone())?.connect().await?;
                let mut client = GuardianControlClient::new(channel);
                let response = client
                    .sign_witness_statement(SignWitnessStatementRequest {
                        statement: statement_bytes,
                        manifest_hash: manifest_hash.to_vec(),
                    })
                    .await?
                    .into_inner();
                Ok::<_, anyhow::Error>(response)
            });
        }

        let mut collected = Vec::new();
        while let Some(result) = inflight.next().await {
            let response = match result {
                Ok(response) => response,
                Err(error) => {
                    tracing::warn!(
                        target: "guardian",
                        event = "witness_remote_sign_failed",
                        error = %error
                    );
                    continue;
                }
            };
            let manifest_hash: [u8; 32] =
                response.manifest_hash.as_slice().try_into().map_err(|_| {
                    anyhow!("remote witness response returned invalid manifest hash")
                })?;
            if manifest_hash != self.manifest_hash {
                return Err(anyhow!("remote witness response manifest hash mismatch"));
            }
            let returned_statement_hash: [u8; 32] =
                response.statement_hash.as_slice().try_into().map_err(|_| {
                    anyhow!("remote witness response returned invalid statement hash")
                })?;
            if returned_statement_hash != statement_hash {
                return Err(anyhow!("remote witness response statement hash mismatch"));
            }
            for partial_signature in response.partial_signatures {
                collected
                    .push(self.verify_remote_partial_signature(statement_hash, partial_signature)?);
            }
        }

        Ok(collected)
    }

    fn verify_remote_partial_signature(
        &self,
        statement_hash: [u8; 32],
        partial_signature: GuardianMemberSignature,
    ) -> Result<(usize, BlsSignature)> {
        let member_index = usize::try_from(partial_signature.member_index)
            .map_err(|_| anyhow!("remote witness response member index overflow"))?;
        let member = self
            .manifest
            .members
            .get(member_index)
            .ok_or_else(|| anyhow!("remote witness response signer outside manifest"))?;
        let signature = BlsSignature::from_bytes(&partial_signature.signature)
            .map_err(|e| anyhow!(e.to_string()))?;
        let public_key =
            BlsPublicKey::from_bytes(&member.public_key).map_err(|e| anyhow!(e.to_string()))?;
        public_key
            .verify(&statement_hash, &signature)
            .map_err(|e| anyhow!(e.to_string()))?;
        Ok((member_index, signature))
    }
}

fn load_bls_private_key(path: &Path) -> Result<BlsPrivateKey> {
    let key_bytes = std::fs::read(path)?;
    if let Ok(raw_text) = std::str::from_utf8(&key_bytes) {
        let trimmed = raw_text.trim();
        let trimmed = trimmed.strip_prefix("0x").unwrap_or(trimmed);
        if !trimmed.is_empty() && trimmed.chars().all(|ch| ch.is_ascii_hexdigit()) {
            return BlsPrivateKey::from_bytes(&hex::decode(trimmed)?)
                .map_err(|e| anyhow!(e.to_string()));
        }
    }
    BlsPrivateKey::from_bytes(&key_bytes).map_err(|e| anyhow!(e.to_string()))
}

/// gRPC-backed signer that delegates consensus certification to the local Guardian runtime.
pub struct GuardianGrpcSigner {
    channel: Channel,
    public_key: Vec<u8>,
    subject: Vec<u8>,
    manifest_hash: [u8; 32],
    measurement_root: [u8; 32],
    policy_hash: [u8; 32],
    checkpoint: Arc<TokioMutex<GuardianDecisionState>>,
}

impl GuardianGrpcSigner {
    /// Connects to the Guardian control-plane endpoint and prepares a signer handle.
    pub async fn connect(endpoint: String, public_key: Vec<u8>, subject: Vec<u8>) -> Result<Self> {
        let endpoint = if endpoint.starts_with("http://") || endpoint.starts_with("https://") {
            endpoint
        } else {
            format!("http://{endpoint}")
        };
        let endpoint_config = Channel::from_shared(endpoint.clone())?;
        let mut last_error = None;
        let mut channel = None;
        for attempt in 0..20 {
            match endpoint_config.clone().connect().await {
                Ok(connected) => {
                    channel = Some(connected);
                    break;
                }
                Err(error) => {
                    last_error = Some(error);
                    if attempt < 19 {
                        tokio::time::sleep(Duration::from_millis(250)).await;
                    }
                }
            }
        }
        let channel = channel.ok_or_else(|| {
            let error = last_error
                .map(|error| error.to_string())
                .unwrap_or_else(|| "guardian gRPC connection failed".to_string());
            anyhow!("failed to connect to guardian control endpoint {endpoint}: {error}")
        })?;
        Ok(Self {
            channel,
            public_key,
            subject,
            manifest_hash: [0u8; 32],
            measurement_root: [0u8; 32],
            policy_hash: [0u8; 32],
            checkpoint: Arc::new(TokioMutex::new(GuardianDecisionState::default())),
        })
    }
}

#[async_trait]
impl GuardianSigner for GuardianGrpcSigner {
    async fn sign_consensus_payload(
        &self,
        payload_hash: [u8; 32],
        height: u64,
        view: u64,
        experimental_witness_manifest: Option<([u8; 32], u8)>,
    ) -> Result<SignatureBundle> {
        let checkpoint = self.checkpoint.lock().await.clone();
        let request = SignConsensusRequest {
            payload_hash: payload_hash.to_vec(),
            subject: self.subject.clone(),
            expected_counter: checkpoint.counter,
            expected_trace_hash: checkpoint.trace_hash.to_vec(),
            measurement_root: self.measurement_root.to_vec(),
            policy_hash: self.policy_hash.to_vec(),
            manifest_hash: self.manifest_hash.to_vec(),
            height,
            view,
            witness_manifest_hash: experimental_witness_manifest
                .map(|(manifest_hash, _)| manifest_hash.to_vec())
                .unwrap_or_default(),
            witness_reassignment_depth: experimental_witness_manifest
                .map(|(_, depth)| u32::from(depth))
                .unwrap_or_default(),
        };

        let mut client = GuardianControlClient::new(self.channel.clone());
        let response = client.sign_consensus(request).await?.into_inner();
        let trace_hash: [u8; 32] = response
            .trace_hash
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("guardian returned invalid trace hash length"))?;
        let guardian_certificate = if response.guardian_certificate.is_empty() {
            None
        } else {
            Some(
                codec::from_bytes_canonical(&response.guardian_certificate)
                    .map_err(|e| anyhow!(e.to_string()))?,
            )
        };

        *self.checkpoint.lock().await = GuardianDecisionState {
            counter: response.counter,
            trace_hash,
            slot_locks: HashMap::new(),
            slot_certificates: HashMap::new(),
        };

        Ok(SignatureBundle {
            signature: response.signature,
            counter: response.counter,
            trace_hash,
            guardian_certificate,
        })
    }

    async fn report_witness_fault(&self, evidence: &GuardianWitnessFaultEvidence) -> Result<()> {
        let mut client = GuardianControlClient::new(self.channel.clone());
        client
            .report_witness_fault(ReportWitnessFaultRequest {
                evidence: codec::to_bytes_canonical(evidence)
                    .map_err(|e| anyhow!(e.to_string()))?,
            })
            .await?;
        Ok(())
    }

    fn public_key(&self) -> Vec<u8> {
        self.public_key.clone()
    }
}

/// A signed attestation for a specific AI model snapshot.
/// Used to authorize the loading of large weights into the Workload container.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ModelAttestation {
    /// The canonical account ID of the validator issuing this attestation.
    pub validator_id: AccountId,
    /// The SHA-256 hash of the model weights file.
    pub model_hash: [u8; 32],
    /// The UNIX timestamp when the attestation was generated.
    pub timestamp: u64,
    /// The cryptographic signature over the attestation data.
    pub signature: Vec<u8>,
}

// --- Guardian Container ---

/// Holds open file handles to the binaries to prevent modification while running.
/// On Linux, writing to an executing file returns ETXTBSY.
pub struct BinaryGuard {
    _handles: Vec<File>,
}

/// The GuardianContainer is the root of trust.
#[derive(Clone)]
pub struct GuardianContainer {
    /// The secure channel to the Orchestrator container.
    pub orchestration_channel: SecurityChannel,
    /// The secure channel to the Workload container.
    pub workload_channel: SecurityChannel,
    is_running: Arc<AtomicBool>,
    /// The path to the directory containing configuration and keys.
    config_dir: PathBuf,
    /// Backend authority for secrets and signing material.
    key_authority: Arc<dyn KeyAuthority>,
    /// Append-only witness logs for receipts and checkpoints.
    transparency_logs: BTreeMap<String, Arc<dyn TransparencyLog>>,
    /// Default transparency log id used for non-committee effects.
    default_transparency_log_id: String,
    /// TLS and attestation verification policy for egress and runtime evidence.
    verifier_policy: GuardianVerifierPolicyConfig,
    /// Deployment profile controlling local fallbacks.
    production_mode: GuardianProductionMode,
    /// Threshold committee used to issue guardianized decisions.
    committee_client: Option<GuardianCommitteeClient>,
    /// Research-only witness committees that can cross-sign guardian decisions.
    witness_committee_clients: HashMap<[u8; 32], GuardianWitnessCommitteeClient>,
    /// Monotonic decision stream shared across consensus and egress certificates.
    decision_state: Arc<TokioMutex<GuardianDecisionState>>,
}

fn digest_to_array(digest: impl AsRef<[u8]>) -> Result<[u8; 32]> {
    digest
        .as_ref()
        .try_into()
        .map_err(|_| anyhow!("sha256 digest was not 32 bytes"))
}

fn normalize_guardian_endpoint(endpoint: &str) -> String {
    if endpoint.starts_with("http://") || endpoint.starts_with("https://") {
        endpoint.to_string()
    } else {
        format!("http://{endpoint}")
    }
}

fn load_transparency_log_signer(config: &GuardianConfig) -> Result<libp2p::identity::Keypair> {
    if let Some(path) = &config.transparency_log.signing_key_path {
        let bytes = std::fs::read(path)?;
        return libp2p::identity::Keypair::from_protobuf_encoding(&bytes)
            .map_err(|e| anyhow!("failed to decode transparency log signer keypair: {e}"));
    }
    if matches!(config.production_mode, GuardianProductionMode::Production) {
        return Err(anyhow!(
            "production guardian profile requires transparency_log.signing_key_path"
        ));
    }
    Ok(libp2p::identity::Keypair::generate_ed25519())
}

fn collect_transparency_log_ids(config: &GuardianConfig) -> BTreeSet<String> {
    let mut log_ids = BTreeSet::new();
    if !config.transparency_log.log_id.trim().is_empty() {
        log_ids.insert(config.transparency_log.log_id.clone());
    }
    if !config.committee.transparency_log_id.trim().is_empty() {
        log_ids.insert(config.committee.transparency_log_id.clone());
    }
    for witness in &config.experimental_witness_committees {
        if !witness.transparency_log_id.trim().is_empty() {
            log_ids.insert(witness.transparency_log_id.clone());
        }
    }
    if log_ids.is_empty() {
        log_ids.insert("guardian-local".to_string());
    }
    log_ids
}

fn parse_target_authority(target_domain: &str) -> Result<(String, u16)> {
    if let Some((host, port)) = target_domain.rsplit_once(':') {
        if !host.is_empty() && !host.contains(']') && !port.is_empty() {
            if let Ok(port) = port.parse::<u16>() {
                return Ok((host.to_string(), port));
            }
        }
    }
    Ok((target_domain.to_string(), 443))
}

pub(crate) fn compute_secure_egress_request_hash(
    method: &str,
    target_domain: &str,
    path: &str,
    body: &[u8],
) -> Result<[u8; 32]> {
    digest_to_array(
        Sha256::digest(
            format!(
                "{}|{}|{}|{}",
                method,
                target_domain,
                path,
                hex::encode(Sha256::digest(body).map_err(|e| anyhow!(e))?)
            )
            .as_bytes(),
        )
        .map_err(|e| anyhow!(e))?,
    )
}

pub(crate) fn compute_secure_egress_transcript_root(
    request_hash: [u8; 32],
    handshake_transcript_hash: [u8; 32],
    request_transcript_hash: [u8; 32],
    response_transcript_hash: [u8; 32],
    peer_certificate_chain_hash: [u8; 32],
    response_hash: [u8; 32],
) -> Result<[u8; 32]> {
    digest_to_array(
        Sha256::digest(
            &[
                handshake_transcript_hash.as_ref(),
                request_transcript_hash.as_ref(),
                response_transcript_hash.as_ref(),
                request_hash.as_ref(),
                peer_certificate_chain_hash.as_ref(),
                response_hash.as_ref(),
            ]
            .concat(),
        )
        .map_err(|e| anyhow!(e))?,
    )
}

fn decode_pinned_hashes(hex_hashes: &[String]) -> Result<Vec<[u8; 32]>> {
    hex_hashes
        .iter()
        .map(|hex_hash| {
            let trimmed = hex_hash.trim().trim_start_matches("0x");
            let bytes = hex::decode(trimmed)?;
            let len = bytes.len();
            bytes
                .try_into()
                .map_err(|_| anyhow!("configured TLS pin must decode to 32 bytes, got {}", len))
        })
        .collect()
}

fn build_tls_root_store(policy: &GuardianVerifierPolicyConfig) -> Result<RootCertStore> {
    let mut root_store = RootCertStore::empty();
    if policy.tls_allowed_root_pem_paths.is_empty() {
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        return Ok(root_store);
    }

    for pem_path in &policy.tls_allowed_root_pem_paths {
        let pem = std::fs::read(pem_path)?;
        let mut reader = std::io::BufReader::new(pem.as_slice());
        let certificates =
            rustls_pemfile::certs(&mut reader).collect::<std::result::Result<Vec<_>, _>>()?;
        root_store.add_parsable_certificates(certificates);
    }
    Ok(root_store)
}

struct TranscriptAccumulator {
    request: Sha256,
    response: Sha256,
}

impl TranscriptAccumulator {
    fn new() -> Self {
        Self {
            request: Sha256::new(),
            response: Sha256::new(),
        }
    }

    fn record_request(&mut self, data: &[u8]) -> io::Result<()> {
        self.request
            .update(data)
            .map(|_| ())
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))
    }

    fn record_response(&mut self, data: &[u8]) -> io::Result<()> {
        self.response
            .update(data)
            .map(|_| ())
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))
    }

    fn finalize(&mut self) -> Result<([u8; 32], [u8; 32])> {
        let request = std::mem::replace(&mut self.request, Sha256::new())
            .finalize()
            .map_err(|e| anyhow!(e.to_string()))?;
        let response = std::mem::replace(&mut self.response, Sha256::new())
            .finalize()
            .map_err(|e| anyhow!(e.to_string()))?;
        Ok((digest_to_array(request)?, digest_to_array(response)?))
    }
}

struct NotarizedTlsStream<S> {
    inner: S,
    transcript: Arc<StdMutex<TranscriptAccumulator>>,
}

impl<S> AsyncRead for NotarizedTlsStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let pre_len = buf.filled().len();
        match Pin::new(&mut self.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                let filled = buf.filled();
                let newly_read = &filled[pre_len..];
                if !newly_read.is_empty() {
                    self.transcript
                        .lock()
                        .map_err(|_| {
                            io::Error::new(io::ErrorKind::Other, "transcript lock poisoned")
                        })?
                        .record_response(newly_read)?;
                }
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

impl<S> AsyncWrite for NotarizedTlsStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match Pin::new(&mut self.inner).poll_write(cx, buf) {
            Poll::Ready(Ok(written)) => {
                if written > 0 {
                    self.transcript
                        .lock()
                        .map_err(|_| {
                            io::Error::new(io::ErrorKind::Other, "transcript lock poisoned")
                        })?
                        .record_request(&buf[..written])?;
                }
                Poll::Ready(Ok(written))
            }
            other => other,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

fn peer_certificate_chain_hash(
    tls_stream: &tokio_rustls::client::TlsStream<TcpStream>,
) -> Result<[u8; 32]> {
    let peer_certs = tls_stream
        .get_ref()
        .1
        .peer_certificates()
        .map(|certificates| certificates.to_vec())
        .unwrap_or_default();
    if peer_certs.is_empty() {
        return Ok([0u8; 32]);
    }

    let mut concatenated = Vec::new();
    for certificate in peer_certs {
        concatenated.extend_from_slice(certificate.as_ref());
    }
    digest_to_array(Sha256::digest(&concatenated).map_err(|e| anyhow!(e))?)
}

fn peer_leaf_certificate_hash(
    tls_stream: &tokio_rustls::client::TlsStream<TcpStream>,
) -> Result<[u8; 32]> {
    let peer_certs = tls_stream
        .get_ref()
        .1
        .peer_certificates()
        .map(|certificates| certificates.to_vec())
        .unwrap_or_default();
    let Some(leaf_certificate) = peer_certs.first() else {
        return Ok([0u8; 32]);
    };
    digest_to_array(Sha256::digest(leaf_certificate.as_ref()).map_err(|e| anyhow!(e))?)
}

fn handshake_exporter_hash(
    tls_stream: &tokio_rustls::client::TlsStream<TcpStream>,
) -> Result<[u8; 32]> {
    let mut exporter = [0u8; 32];
    tls_stream
        .get_ref()
        .1
        .export_keying_material(&mut exporter, b"ioi-egress-transcript-v1", None)
        .map_err(|e| anyhow!(e.to_string()))?;
    Ok(exporter)
}

async fn notarized_https_request(
    target_domain: &str,
    path: &str,
    method: &str,
    body: Vec<u8>,
    headers: Vec<(&'static str, String)>,
    policy: &GuardianVerifierPolicyConfig,
) -> Result<(
    Vec<u8>,
    String,
    [u8; 32],
    [u8; 32],
    [u8; 32],
    [u8; 32],
    [u8; 32],
)> {
    let (server_name, port) = parse_target_authority(target_domain)?;
    if !policy.tls_allowed_server_names.is_empty()
        && !policy
            .tls_allowed_server_names
            .iter()
            .any(|allowed_name| allowed_name == &server_name)
    {
        return Err(anyhow!(
            "TLS server name '{}' is not allowed by verifier policy",
            server_name
        ));
    }

    let root_store = build_tls_root_store(policy)?;
    let client_config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(client_config));
    let tcp_stream = TcpStream::connect((server_name.as_str(), port)).await?;
    let rustls_server_name =
        ServerName::try_from(server_name.clone()).map_err(|e| anyhow!(e.to_string()))?;
    let tls_stream = connector.connect(rustls_server_name, tcp_stream).await?;

    let peer_cert_hash = peer_certificate_chain_hash(&tls_stream)?;
    let peer_leaf_hash = peer_leaf_certificate_hash(&tls_stream)?;
    let pinned_leaf_hashes = decode_pinned_hashes(&policy.tls_pinned_leaf_certificate_sha256)?;
    if !pinned_leaf_hashes.is_empty() && !pinned_leaf_hashes.contains(&peer_leaf_hash) {
        return Err(anyhow!(
            "peer leaf certificate hash does not match any configured TLS pin"
        ));
    }
    let handshake_hash = handshake_exporter_hash(&tls_stream)?;
    let transcript = Arc::new(StdMutex::new(TranscriptAccumulator::new()));
    let notarized_stream = NotarizedTlsStream {
        inner: tls_stream,
        transcript: transcript.clone(),
    };
    let (mut sender, connection) = http1::handshake(TokioIo::new(notarized_stream)).await?;
    tokio::spawn(async move {
        let _ = connection.await;
    });

    let mut builder = HttpRequest::builder()
        .method(method)
        .uri(path)
        .header("host", target_domain)
        .header("content-type", "application/json")
        .header("accept-encoding", "identity")
        .header("connection", "close");
    for (header_name, header_value) in headers {
        builder = builder.header(header_name, header_value);
    }

    let response = sender
        .send_request(builder.body(Full::new(Bytes::from(body)))?)
        .await?;
    let response_bytes = response.collect().await?.to_bytes().to_vec();
    drop(sender);

    let (request_transcript_hash, response_transcript_hash) = transcript
        .lock()
        .map_err(|_| anyhow!("transcript lock poisoned"))?
        .finalize()?;

    Ok((
        response_bytes,
        server_name,
        peer_cert_hash,
        peer_leaf_hash,
        handshake_hash,
        request_transcript_hash,
        response_transcript_hash,
    ))
}

/// Generates a self-signed CA and server/client certificates for mTLS.
pub fn generate_certificates_if_needed(certs_dir: &Path) -> Result<()> {
    if certs_dir.join("ca.pem").exists() {
        return Ok(());
    }
    log::info!(
        "Generating mTLS CA and certificates in {}",
        certs_dir.display()
    );
    std::fs::create_dir_all(certs_dir)?;

    // [FIX] rcgen 0.13 changes: CertificateParams::new returns Result
    let mut ca_params = CertificateParams::new(vec!["IOI Kernel Local CA".to_string()])?;
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];

    // [FIX] Generate keypair explicitly
    let ca_keypair = KeyPair::generate()?;
    // [FIX] Use self_signed
    let ca_cert = ca_params.self_signed(&ca_keypair)?;

    // [FIX] Use pem() instead of serialize_pem()
    std::fs::write(certs_dir.join("ca.pem"), ca_cert.pem())?;
    std::fs::write(certs_dir.join("ca.key"), ca_keypair.serialize_pem())?;

    let signers = [
        ("guardian-server", vec!["guardian", "localhost"]),
        ("workload-server", vec!["workload", "localhost"]),
        ("orchestration", vec![]),
        ("workload", vec![]),
    ];
    for (name, domains) in &signers {
        // [FIX] CertificateParams::new returns Result
        let mut params = CertificateParams::new(vec![name.to_string()])?;
        params.subject_alt_names = domains
            .iter()
            .map(|d| {
                // [FIX] Use Ia5String for DnsName
                SanType::DnsName(Ia5String::try_from(d.to_string()).expect("valid dns name"))
            })
            .chain(vec![SanType::IpAddress(Ipv4Addr::LOCALHOST.into())])
            .collect();

        let keypair = KeyPair::generate()?;
        // [FIX] Use signed_by
        let cert = params.signed_by(&keypair, &ca_cert, &ca_keypair)?;

        std::fs::write(certs_dir.join(format!("{}.pem", name)), cert.pem())?;
        std::fs::write(
            certs_dir.join(format!("{}.key", name)),
            keypair.serialize_pem(),
        )?;
    }
    Ok(())
}

impl GuardianContainer {
    /// Creates a new Guardian container instance.
    pub fn new(
        config_dir: PathBuf,
        config: GuardianConfig,
        validator_account_id: AccountId,
    ) -> Result<Self> {
        let key_authority: Arc<dyn KeyAuthority> = Arc::from(build_key_authority(
            config.key_authority.clone(),
            config.production_mode,
        )?);
        let default_transparency_log_id = if config.transparency_log.log_id.trim().is_empty() {
            if config.committee.transparency_log_id.trim().is_empty() {
                "guardian-local".to_string()
            } else {
                config.committee.transparency_log_id.clone()
            }
        } else {
            config.transparency_log.log_id.clone()
        };
        let transparency_log_signer = load_transparency_log_signer(&config)?;
        let transparency_log_signer_bytes = transparency_log_signer
            .to_protobuf_encoding()
            .map_err(|e| anyhow!("failed to encode transparency log signer: {e}"))?;
        let transparency_logs = collect_transparency_log_ids(&config)
            .into_iter()
            .map(|log_id| {
                let signer = libp2p::identity::Keypair::from_protobuf_encoding(
                    &transparency_log_signer_bytes,
                )
                .map_err(|e| anyhow!("failed to decode transparency log signer: {e}"))?;
                Ok::<_, anyhow::Error>((
                    log_id.clone(),
                    Arc::new(MemoryTransparencyLog::new(log_id, signer))
                        as Arc<dyn TransparencyLog>,
                ))
            })
            .collect::<Result<BTreeMap<_, _>>>()?;
        let committee_client = GuardianCommitteeClient::from_config(&config, validator_account_id)?;
        let witness_committee_clients = GuardianWitnessCommitteeClient::from_configs(&config)?;
        Ok(Self {
            orchestration_channel: SecurityChannel::new("guardian", "orchestration"),
            workload_channel: SecurityChannel::new("guardian", "workload"),
            is_running: Arc::new(AtomicBool::new(false)),
            config_dir,
            key_authority,
            transparency_logs,
            default_transparency_log_id,
            verifier_policy: config.verifier_policy.clone(),
            production_mode: config.production_mode,
            committee_client,
            witness_committee_clients,
            decision_state: Arc::new(TokioMutex::new(GuardianDecisionState::default())),
        })
    }

    fn transparency_log_for(&self, log_id: &str) -> Result<Arc<dyn TransparencyLog>> {
        self.transparency_logs
            .get(log_id)
            .cloned()
            .ok_or_else(|| anyhow!("guardian transparency log '{log_id}' is not configured"))
    }

    fn default_transparency_log(&self) -> Result<Arc<dyn TransparencyLog>> {
        self.transparency_log_for(&self.default_transparency_log_id)
    }

    async fn issue_guardian_quorum_certificate(
        &self,
        domain: GuardianDecisionDomain,
        slot: Option<(u64, u64)>,
        subject: Vec<u8>,
        payload_hash: [u8; 32],
        expected_counter: u64,
        expected_trace_hash: [u8; 32],
        requested_measurement_root: Option<[u8; 32]>,
        requested_policy_hash: Option<[u8; 32]>,
        requested_manifest_hash: Option<[u8; 32]>,
    ) -> Result<Option<(u64, [u8; 32], GuardianQuorumCertificate)>> {
        let Some(committee_client) = &self.committee_client else {
            return Ok(None);
        };

        if let Some(manifest_hash) = requested_manifest_hash.filter(|hash| *hash != [0u8; 32]) {
            if manifest_hash != committee_client.manifest_hash() {
                return Err(anyhow!(
                    "requested guardian manifest hash does not match local committee"
                ));
            }
        }

        let mut decision_state = self.decision_state.lock().await;
        if let Some(slot) = slot {
            if let Some(locked_payload_hash) = decision_state.slot_locks.get(&slot) {
                if locked_payload_hash != &payload_hash {
                    return Err(anyhow!(
                        "guardian slot already certified for a different payload at height {} view {}",
                        slot.0,
                        slot.1
                    ));
                }
                if let Some(existing_certificate) =
                    decision_state.slot_certificates.get(&slot).cloned()
                {
                    return Ok(Some((
                        existing_certificate.counter,
                        existing_certificate.trace_hash,
                        existing_certificate,
                    )));
                }
            }
        }
        if expected_counter != 0 && expected_counter != decision_state.counter {
            return Err(anyhow!(
                "guardian counter checkpoint mismatch: expected {}, current {}",
                expected_counter,
                decision_state.counter
            ));
        }
        if expected_trace_hash != [0u8; 32] && expected_trace_hash != decision_state.trace_hash {
            return Err(anyhow!("guardian trace checkpoint mismatch"));
        }
        let counter = decision_state.counter.saturating_add(1);
        let trace_hash = digest_to_array(
            Sha256::digest(
                &[
                    decision_state.trace_hash.as_ref(),
                    payload_hash.as_ref(),
                    counter.to_be_bytes().as_ref(),
                    committee_client.manifest_hash().as_ref(),
                ]
                .concat(),
            )
            .map_err(|e| anyhow!(e))?,
        )?;
        let decision = GuardianDecision {
            domain: domain as u8,
            subject: if subject.is_empty() {
                committee_client.default_subject()
            } else {
                subject
            },
            payload_hash,
            counter,
            trace_hash,
            measurement_root: requested_measurement_root
                .filter(|hash| *hash != [0u8; 32])
                .unwrap_or_else(|| committee_client.default_measurement_root()),
            policy_hash: requested_policy_hash
                .filter(|hash| *hash != [0u8; 32])
                .unwrap_or_else(|| committee_client.default_policy_hash()),
        };

        let transparency_log_id = if committee_client
            .manifest
            .transparency_log_id
            .trim()
            .is_empty()
        {
            self.default_transparency_log_id.clone()
        } else {
            committee_client.manifest.transparency_log_id.clone()
        };
        let transparency_log = self.transparency_log_for(&transparency_log_id)?;
        let mut certificate = committee_client.sign_decision(&decision, slot).await?;
        let checkpoint_payload = codec::to_bytes_canonical(&(&decision, &certificate))
            .map_err(|e| anyhow!(e.to_string()))?;
        certificate.log_checkpoint = Some(transparency_log.append(&checkpoint_payload).await?);

        decision_state.counter = counter;
        decision_state.trace_hash = trace_hash;
        if let Some(slot) = slot {
            decision_state.slot_locks.insert(slot, payload_hash);
            decision_state
                .slot_certificates
                .insert(slot, certificate.clone());
        }

        Ok(Some((counter, trace_hash, certificate)))
    }

    async fn issue_experimental_witness_certificate(
        &self,
        guardian_certificate: &GuardianQuorumCertificate,
        witness_manifest_hash: [u8; 32],
        reassignment_depth: u8,
        producer_account_id: AccountId,
        height: u64,
        view: u64,
    ) -> Result<GuardianWitnessCertificate> {
        let witness_client = self
            .witness_committee_clients
            .get(&witness_manifest_hash)
            .ok_or_else(|| {
                anyhow!("requested witness manifest is not configured on this guardian")
            })?;
        let transparency_log_id = if witness_client
            .manifest
            .transparency_log_id
            .trim()
            .is_empty()
        {
            self.default_transparency_log_id.clone()
        } else {
            witness_client.manifest.transparency_log_id.clone()
        };
        let transparency_log = self.transparency_log_for(&transparency_log_id)?;
        let statement = GuardianWitnessStatement {
            producer_account_id,
            height,
            view,
            guardian_manifest_hash: guardian_certificate.manifest_hash,
            guardian_decision_hash: guardian_certificate.decision_hash,
            guardian_counter: guardian_certificate.counter,
            guardian_trace_hash: guardian_certificate.trace_hash,
            guardian_measurement_root: guardian_certificate.measurement_root,
            guardian_checkpoint_root: guardian_certificate
                .log_checkpoint
                .as_ref()
                .map(|checkpoint| checkpoint.root_hash)
                .unwrap_or([0u8; 32]),
        };
        let mut witness_certificate = witness_client
            .sign_witness_statement(&statement, reassignment_depth)
            .await?;
        let checkpoint_payload = codec::to_bytes_canonical(&(&statement, &witness_certificate))
            .map_err(|e| anyhow!(e.to_string()))?;
        witness_certificate.log_checkpoint =
            Some(transparency_log.append(&checkpoint_payload).await?);
        Ok(witness_certificate)
    }

    /// Appends witness-fault evidence to the guardian transparency log and returns the resulting
    /// checkpoint.
    pub async fn report_witness_fault_evidence(
        &self,
        evidence: &GuardianWitnessFaultEvidence,
    ) -> Result<GuardianLogCheckpoint> {
        let payload = codec::to_bytes_canonical(evidence).map_err(|e| anyhow!(e.to_string()))?;
        self.default_transparency_log()?.append(&payload).await
    }

    /// Signs a consensus payload through the configured guardian committee and returns the legacy
    /// signature plus the emitted guardian quorum certificate.
    pub async fn sign_consensus_with_guardian(
        &self,
        signer: &libp2p::identity::Keypair,
        payload_hash: [u8; 32],
        height: u64,
        view: u64,
        subject: Vec<u8>,
        expected_counter: u64,
        expected_trace_hash: [u8; 32],
        requested_measurement_root: Option<[u8; 32]>,
        requested_policy_hash: Option<[u8; 32]>,
        requested_manifest_hash: Option<[u8; 32]>,
        requested_witness_manifest_hash: Option<[u8; 32]>,
        witness_reassignment_depth: u8,
    ) -> Result<SignatureBundle> {
        let producer_account_id = requested_witness_manifest_hash
            .filter(|hash| *hash != [0u8; 32])
            .map(|_| {
                subject
                    .as_slice()
                    .try_into()
                    .map(AccountId)
                    .map_err(|_| anyhow!("consensus subject must be a 32-byte account id"))
            })
            .transpose()?;
        let (counter, trace_hash, mut guardian_certificate) = self
            .issue_guardian_quorum_certificate(
                GuardianDecisionDomain::ConsensusSlot,
                Some((height, view)),
                subject.clone(),
                payload_hash,
                expected_counter,
                expected_trace_hash,
                requested_measurement_root,
                requested_policy_hash,
                requested_manifest_hash,
            )
            .await?
            .ok_or_else(|| anyhow!("guardian committee signing is not configured"))?;

        if let Some(witness_manifest_hash) =
            requested_witness_manifest_hash.filter(|hash| *hash != [0u8; 32])
        {
            guardian_certificate.experimental_witness_certificate = Some(
                self.issue_experimental_witness_certificate(
                    &guardian_certificate,
                    witness_manifest_hash,
                    witness_reassignment_depth,
                    producer_account_id
                        .ok_or_else(|| anyhow!("missing witness producer account id"))?,
                    height,
                    view,
                )
                .await?,
            );
        }

        let mut signed_payload = Vec::with_capacity(32 + 8 + 32);
        signed_payload.extend_from_slice(&payload_hash);
        signed_payload.extend_from_slice(&counter.to_be_bytes());
        signed_payload.extend_from_slice(&trace_hash);

        Ok(SignatureBundle {
            signature: signer.sign(&signed_payload)?,
            counter,
            trace_hash,
            guardian_certificate: Some(guardian_certificate),
        })
    }

    /// Signs a canonical guardian decision with the local committee member keys hosted by this
    /// Guardian instance. Used by remote committee fan-out to gather partial BLS signatures.
    pub async fn sign_committee_decision_members(
        &self,
        decision: &GuardianDecision,
        requested_manifest_hash: Option<[u8; 32]>,
        slot: Option<(u64, u64)>,
    ) -> Result<Vec<(usize, BlsSignature)>> {
        let Some(committee_client) = &self.committee_client else {
            return Err(anyhow!("guardian committee signing is not configured"));
        };

        if let Some(manifest_hash) = requested_manifest_hash.filter(|hash| *hash != [0u8; 32]) {
            if manifest_hash != committee_client.manifest_hash() {
                return Err(anyhow!(
                    "requested guardian manifest hash does not match local committee"
                ));
            }
        }

        let mut decision_state = self.decision_state.lock().await;
        let expected_counter = decision_state.counter.saturating_add(1);
        if decision.counter != expected_counter {
            return Err(anyhow!(
                "committee decision counter mismatch: expected {}, got {}",
                expected_counter,
                decision.counter
            ));
        }

        let expected_trace_hash = digest_to_array(
            Sha256::digest(
                &[
                    decision_state.trace_hash.as_ref(),
                    decision.payload_hash.as_ref(),
                    decision.counter.to_be_bytes().as_ref(),
                    committee_client.manifest_hash().as_ref(),
                ]
                .concat(),
            )
            .map_err(|e| anyhow!(e))?,
        )?;
        if decision.trace_hash != expected_trace_hash {
            return Err(anyhow!("committee decision trace hash mismatch"));
        }
        if let Some(slot) = slot {
            if let Some(locked_payload_hash) = decision_state.slot_locks.get(&slot) {
                if locked_payload_hash != &decision.payload_hash {
                    return Err(anyhow!(
                        "guardian slot already certified for a different payload at height {} view {}",
                        slot.0,
                        slot.1
                    ));
                }
            }
        }

        let decision_hash =
            canonical_decision_hash(decision).map_err(|e| anyhow!(e.to_string()))?;
        let member_signatures = committee_client
            .signer_keys
            .iter()
            .map(|(member_index, signing_key)| {
                signing_key
                    .sign(&decision_hash)
                    .map(|signature| (*member_index, signature))
                    .map_err(|e| anyhow!(e.to_string()))
            })
            .collect::<Result<Vec<_>>>()?;

        decision_state.counter = decision.counter;
        decision_state.trace_hash = decision.trace_hash;
        if let Some(slot) = slot {
            decision_state
                .slot_locks
                .insert(slot, decision.payload_hash);
        }

        Ok(member_signatures)
    }

    /// Signs a witness statement with the local witness committee member keys hosted by this
    /// Guardian instance. Used by remote witness fan-out to gather partial BLS signatures.
    pub async fn sign_witness_statement_members(
        &self,
        statement: &GuardianWitnessStatement,
        requested_manifest_hash: Option<[u8; 32]>,
    ) -> Result<Vec<(usize, BlsSignature)>> {
        let manifest_hash = requested_manifest_hash
            .filter(|hash| *hash != [0u8; 32])
            .ok_or_else(|| anyhow!("witness manifest hash is required"))?;
        let witness_client = self
            .witness_committee_clients
            .get(&manifest_hash)
            .ok_or_else(|| anyhow!("requested witness manifest is not configured"))?;
        let statement_hash =
            canonical_witness_statement_hash(statement).map_err(|e| anyhow!(e.to_string()))?;
        witness_client
            .signer_keys
            .iter()
            .map(|(member_index, signing_key)| {
                signing_key
                    .sign(&statement_hash)
                    .map(|signature| (*member_index, signature))
                    .map_err(|e| anyhow!(e.to_string()))
            })
            .collect()
    }

    /// Attests to the integrity of an agentic model file by computing its hash.
    pub async fn attest_weights(&self, model_path: &str) -> Result<Vec<u8>, String> {
        let model_bytes = std::fs::read(model_path)
            .map_err(|e| format!("Failed to read agentic model file: {}", e))?;
        // FIX: Remove explicit type annotation to allow compiler inference
        let local_hash_array = Sha256::digest(&model_bytes).map_err(|e| e.to_string())?;
        log::info!(
            "[Guardian] Computed local model hash: {}",
            hex::encode(&local_hash_array)
        );
        Ok(local_hash_array.to_vec())
    }

    /// Measures a model file and issues an attestation.
    /// This is called before the Workload is allowed to load the model into VRAM.
    pub async fn attest_model_snapshot(
        &self,
        keypair: &libp2p::identity::Keypair,
        model_path: &Path,
    ) -> Result<ModelAttestation> {
        log::info!("[Guardian] Attesting model snapshot at {:?}", model_path);

        if !model_path.exists() {
            return Err(anyhow!("Model file not found: {:?}", model_path));
        }

        // Compute SHA-256 of the model file
        // For large models (GBs), we stream read.
        let mut file = File::open(model_path)?;
        let mut hasher = Sha256::new();
        let mut buffer = [0; 8192];

        loop {
            let count = file.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            hasher
                .update(&buffer[..count])
                .map_err(|e| anyhow!(e.to_string()))?;
        }

        let hash_digest = hasher.finalize().map_err(|e| anyhow!(e.to_string()))?;
        let mut model_hash = [0u8; 32];
        // [FIX] Unwrap the result of finalize() before using as_ref() and handle error with ?
        model_hash.copy_from_slice(hash_digest.as_ref());

        // Construct attestation
        let pk_bytes = keypair.public().encode_protobuf();
        // [FIX] Use SignatureSuite::ED25519
        let account_hash = account_id_from_key_material(SignatureSuite::ED25519, &pk_bytes)
            .map_err(|e| anyhow!(e))?;

        let mut attestation = ModelAttestation {
            validator_id: AccountId(account_hash),
            model_hash,
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
            signature: Vec::new(),
        };

        // Sign the deterministic tuple (validator_id, model_hash, timestamp)
        // Note: Real impl would use a dedicated serialization for signing
        let sign_payload = bincode::serialize(&(
            &attestation.validator_id,
            &attestation.model_hash,
            &attestation.timestamp,
        ))?;
        attestation.signature = keypair.sign(&sign_payload)?;

        log::info!(
            "[Guardian] Generated attestation for model hash: {}",
            hex::encode(model_hash)
        );
        Ok(attestation)
    }

    /// Generates a signed `BootAttestation` by hashing the local binaries.
    ///
    /// # Arguments
    /// * `keypair`: The identity keypair used to sign the attestation.
    /// * `config`: The Guardian configuration (used to resolve binary paths).
    pub fn generate_boot_attestation(
        &self,
        keypair: &libp2p::identity::Keypair,
        config: &GuardianConfig,
    ) -> Result<BootAttestation> {
        // Resolve binary directory
        let bin_dir = if let Some(dir) = &config.binary_dir_override {
            Path::new(dir).to_path_buf()
        } else {
            std::env::current_exe()?
                .parent()
                .ok_or(anyhow!("Cannot determine binary directory"))?
                .to_path_buf()
        };

        let measure = |name: &str| -> Result<BinaryMeasurement> {
            let path = bin_dir.join(name);
            if !path.exists() {
                return Err(anyhow!("Binary not found: {:?}", path));
            }
            let bytes = std::fs::read(&path)?;
            let hash = Sha256::digest(&bytes).map_err(|e| anyhow!(e))?;
            let mut sha256 = [0u8; 32];
            sha256.copy_from_slice(&hash);

            Ok(BinaryMeasurement {
                name: name.to_string(),
                sha256,
                size: bytes.len() as u64,
            })
        };

        let guardian_meas = measure("guardian")?;
        let orch_meas = measure("orchestration")?;
        let workload_meas = measure("workload")?;

        let pk_bytes = keypair.public().encode_protobuf();
        // Assuming Ed25519 for the identity key
        // [FIX] Use SignatureSuite::ED25519
        let account_hash = account_id_from_key_material(SignatureSuite::ED25519, &pk_bytes)
            .map_err(|e| anyhow!(e))?;

        let mut attestation = BootAttestation {
            validator_account_id: AccountId(account_hash),
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
            guardian: guardian_meas,
            orchestration: orch_meas,
            workload: workload_meas,
            build_metadata: env!("CARGO_PKG_VERSION").to_string(), // Or inject git hash via env
            signature: Vec::new(),
        };

        // Sign it
        let sign_bytes = attestation.to_sign_bytes()?;
        let signature = keypair.sign(&sign_bytes)?;
        attestation.signature = signature;

        log::info!(
            "[Guardian] Generated BootAttestation for validator {}. Guardian Hash: {}",
            hex::encode(account_hash),
            hex::encode(attestation.guardian.sha256)
        );

        Ok(attestation)
    }

    /// Locates, hashes, and locks sibling binaries relative to the current executable.
    pub fn verify_binaries(&self, config: &GuardianConfig) -> Result<Option<BinaryGuard>> {
        // If explicit opt-out, warn loudly.
        if !config.enforce_binary_integrity {
            tracing::warn!(
                "SECURITY WARNING: Binary integrity enforcement is DISABLED. \
                This node is vulnerable to runtime binary swapping attacks."
            );
            return Ok(None);
        }

        // Use override if present, otherwise resolve relative to current executable.
        let bin_dir = if let Some(dir) = &config.binary_dir_override {
            Path::new(dir).to_path_buf()
        } else {
            let my_path = std::env::current_exe()?;
            my_path
                .parent()
                .ok_or(anyhow!("Cannot determine binary directory"))?
                .to_path_buf()
        };

        let orch_path = bin_dir.join("orchestration");
        let work_path = bin_dir.join("workload");

        // If enabled (default), hashes MUST be present.
        let orch_hash = config.approved_orchestrator_hash.as_deref().ok_or_else(|| {
            anyhow!("Guardian failed to start: `enforce_binary_integrity` is true, but `approved_orchestrator_hash` is missing in guardian.toml")
        })?;

        let work_hash = config.approved_workload_hash.as_deref().ok_or_else(|| {
            anyhow!("Guardian failed to start: `enforce_binary_integrity` is true, but `approved_workload_hash` is missing in guardian.toml")
        })?;

        let orch_handle = self.check_binary(&orch_path, Some(orch_hash), "Orchestrator")?;
        let work_handle = self.check_binary(&work_path, Some(work_hash), "Workload")?;

        log::info!("[Guardian] Binary integrity verified. Executables locked.");

        Ok(Some(BinaryGuard {
            _handles: vec![orch_handle, work_handle],
        }))
    }

    fn check_binary(&self, path: &Path, expected_hash: Option<&str>, label: &str) -> Result<File> {
        let expected = expected_hash.ok_or_else(|| {
            anyhow!(
                "Integrity enforcement enabled but no hash provided for {}",
                label
            )
        })?;

        log::info!("[Guardian] Verifying {} at {:?}", label, path);

        // Open file for reading (this handle ensures the file exists and locks it if OS supports)
        let mut file =
            File::open(path).map_err(|e| anyhow!("Failed to open {} binary: {}", label, e))?;

        // Read entire binary into memory for hashing
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)?;

        // Compute SHA-256 using dcrypt
        let digest = Sha256::digest(&buffer).map_err(|e| anyhow!("Hashing failed: {}", e))?;
        let hex_digest = hex::encode(digest);

        if hex_digest != expected {
            return Err(anyhow!(
                "SECURITY VIOLATION: {} binary hash mismatch!\nExpected: {}\nComputed: {}",
                label,
                expected,
                hex_digest
            ));
        }

        // Return the open file handle to keep a lock reference (OS dependent)
        Ok(file)
    }

    /// Resolves the secure passphrase from environment or interactive prompt.
    fn resolve_passphrase(confirm: bool) -> Result<String> {
        if let Ok(p) = std::env::var("IOI_GUARDIAN_KEY_PASS") {
            return Ok(p);
        }

        if atty::is(atty::Stream::Stdin) {
            eprint!("Enter Guardian Key Passphrase: ");
            std::io::stderr().flush()?;
            let pass = rpassword::read_password()?;

            if confirm {
                eprint!("Confirm Passphrase: ");
                std::io::stderr().flush()?;
                let conf = rpassword::read_password()?;
                if pass != conf {
                    return Err(anyhow!("Passphrases do not match"));
                }
            }

            if pass.is_empty() {
                return Err(anyhow!("Empty passphrase not allowed"));
            }
            Ok(pass)
        } else {
            Err(anyhow!(
                "No TTY and IOI_GUARDIAN_KEY_PASS not set. Cannot decrypt key."
            ))
        }
    }

    /// Loads an encrypted key file from disk, decrypts it, and returns the raw bytes.
    /// Rejects raw 32-byte keys (legacy seeds) to enforce encryption-at-rest.
    pub fn load_encrypted_file(path: &Path) -> Result<Vec<u8>> {
        let content = std::fs::read(path)?;

        // Check for Magic Header defined in ioi_crypto::key_store
        if content.starts_with(b"IOI-GKEY") {
            let pass = Self::resolve_passphrase(false)?;
            let secret = decrypt_key(&content, &pass)?;
            // secret is SensitiveBytes(Vec<u8>), needs explicit clone to move out
            Ok(secret.0.clone())
        } else {
            // Safety check for legacy/raw keys.
            if content.len() == 32 {
                return Err(anyhow!(
                    "SECURITY ERROR: Found unsafe raw key at {:?}. \
                    The IOI Kernel requires all validator keys to be encrypted. \
                    Please delete this file to generate a new secure key, or migrate it manually.",
                    path
                ));
            }
            // Support previous magic if transitioning
            if content.starts_with(b"IOI_ENC_V1") {
                let _pass = Self::resolve_passphrase(false)?;
                // Using the updated decrypt_key might fail if logic changed strictly.
                // We assume complete migration or compatible logic.
                // But updated decrypt_key checks for IOI-GKEY.
                return Err(anyhow!(
                    "Legacy encrypted key found. Please migrate to V1 format."
                ));
            }

            Err(anyhow!(
                "Unknown key file format or unencrypted file. Encryption is mandatory."
            ))
        }
    }

    /// Encrypts the provided data with a passphrase and saves it to disk using Atomic Write.
    /// 1. Writes to temp file.
    /// 2. Fsyncs.
    /// 3. Renames to final path.
    pub fn save_encrypted_file(path: &Path, data: &[u8]) -> Result<()> {
        println!("--- Encrypting New Secure Key ---");
        let pass = Self::resolve_passphrase(true)?;
        let encrypted = encrypt_key(data, &pass)?;

        // Atomic write pattern: Write to .tmp, sync, rename
        let mut temp_path = path.to_path_buf();
        if let Some(ext) = path.extension() {
            let mut ext_str = ext.to_os_string();
            ext_str.push(".tmp");
            temp_path.set_extension(ext_str);
        } else {
            temp_path.set_extension("tmp");
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&temp_path)?;
            file.write_all(&encrypted)?;
            file.sync_all()?;
        }
        #[cfg(not(unix))]
        {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&temp_path)?;
            file.write_all(&encrypted)?;
            file.sync_all()?;
        }

        std::fs::rename(temp_path, path)?;

        Ok(())
    }

    /// Executes a secure HTTP call on behalf of a workload.
    pub async fn secure_http_call(
        &self,
        target_domain: &str,
        path: &str,
        method: &str,
        body: Vec<u8>,
        secret_id: &str,
        signer: &libp2p::identity::Keypair,
        json_patch_path: Option<&str>, // [NEW] Added parameter
    ) -> Result<(Vec<u8>, [u8; 32], Vec<u8>, EgressReceipt)> {
        // 1. Resolve the secret through the configured authority.
        let key_path = self.config_dir.join(format!("{}.key", secret_id));
        let pass = if matches!(self.production_mode, GuardianProductionMode::Development) {
            Some(Self::resolve_passphrase(false)?)
        } else {
            std::env::var("IOI_GUARDIAN_KEY_PASS").ok()
        };
        let secret_value = self
            .key_authority
            .resolve_secret_string(&key_path, pass.as_deref())
            .await?;

        // 2. Prepare the canonical request hash before secrets are injected.
        let request_hash = compute_secure_egress_request_hash(method, target_domain, path, &body)?;
        let mut extra_headers = Vec::new();

        // 3. Inject Secret (Header vs. Body)
        let final_body = if let Some(patch_path) = json_patch_path {
            // Body Injection (UCP)
            let mut json_body: Value = serde_json::from_slice(&body)
                .map_err(|e| anyhow!("Failed to parse body for injection: {}", e))?;

            // Simple recursive patch helper
            fn patch_json(value: &mut Value, path_parts: &[&str], secret: &str) -> Result<()> {
                if path_parts.is_empty() {
                    if value.is_string() {
                        // Replace template with secret
                        *value = Value::String(secret.to_string());
                        return Ok(());
                    }
                    return Err(anyhow!("Target field is not a string"));
                }

                let (head, tail) = path_parts.split_first().unwrap();

                // Handle array indexing (e.g., "handlers[0]")
                if head.ends_with(']') {
                    if let Some(open_idx) = head.find('[') {
                        let field_name = &head[..open_idx];
                        let idx_str = &head[open_idx + 1..head.len() - 1];
                        let idx: usize = idx_str.parse()?;

                        let array_field = value
                            .get_mut(field_name)
                            .ok_or(anyhow!("Field {} not found", field_name))?;

                        let item = array_field
                            .get_mut(idx)
                            .ok_or(anyhow!("Index {} out of bounds", idx))?;

                        return patch_json(item, tail, secret);
                    }
                }

                let next_val = value
                    .get_mut(*head)
                    .ok_or(anyhow!("Field {} not found", head))?;
                patch_json(next_val, tail, secret)
            }

            // Split path "payment.handlers[0].token" -> handling array syntax needs parsing
            // For MVP, assume simple dot notation or custom parser.
            // Simplified: "payment.handlers.0.token"
            let parts: Vec<&str> = patch_path.split('.').collect();
            patch_json(&mut json_body, &parts, &secret_value)?;

            serde_json::to_vec(&json_body)?
        } else {
            // Header Injection (Standard API)
            extra_headers.push(("authorization", format!("Bearer {}", secret_value)));
            body
        };

        // 4. Execute Request
        let (
            response_bytes,
            server_name,
            cert_hash,
            leaf_cert_hash,
            handshake_transcript_hash,
            request_transcript_hash,
            response_transcript_hash,
        ) = notarized_https_request(
            target_domain,
            path,
            method,
            final_body,
            extra_headers,
            &self.verifier_policy,
        )
        .await?;
        let response_hash =
            digest_to_array(Sha256::digest(&response_bytes).map_err(|e| anyhow!(e))?)?;
        let transcript_root = compute_secure_egress_transcript_root(
            request_hash,
            handshake_transcript_hash,
            request_transcript_hash,
            response_transcript_hash,
            cert_hash,
            response_hash,
        )?;
        let policy_hash = digest_to_array(
            Sha256::digest(
                format!("{}|{}", secret_id, json_patch_path.unwrap_or("header")).as_bytes(),
            )
            .map_err(|e| anyhow!(e))?,
        )?;

        let guardian_certificate = self
            .issue_guardian_quorum_certificate(
                GuardianDecisionDomain::SecureEgress,
                None,
                target_domain.as_bytes().to_vec(),
                transcript_root,
                0,
                [0u8; 32],
                None,
                Some(policy_hash),
                None,
            )
            .await?
            .map(|(_, _, certificate)| certificate);

        // 6. Sign the receipt-compatible attestation.
        let signature =
            self.sign_egress_attestation(signer, target_domain, &cert_hash, &response_bytes)?;
        let checkpoint = self.default_transparency_log()?.append(&signature).await?;
        let receipt = EgressReceipt {
            request_hash,
            server_name,
            transcript_version: self.verifier_policy.tls_transcript_version,
            transcript_root,
            handshake_transcript_hash,
            request_transcript_hash,
            response_transcript_hash,
            peer_certificate_chain_hash: cert_hash,
            peer_leaf_certificate_hash: leaf_cert_hash,
            response_hash,
            policy_hash,
            guardian_certificate,
            log_checkpoint: Some(checkpoint),
        };

        Ok((response_bytes, cert_hash, signature, receipt))
    }

    fn sign_egress_attestation(
        &self,
        signer: &libp2p::identity::Keypair,
        domain: &str,
        cert: &[u8],
        body: &[u8],
    ) -> Result<Vec<u8>> {
        let mut payload = Vec::new();
        payload.extend_from_slice(domain.as_bytes());
        payload.extend_from_slice(cert);
        let body_hash = Sha256::digest(body).map_err(|e| anyhow!(e))?;
        payload.extend_from_slice(&body_hash);

        let signature = signer.sign(&payload)?;
        Ok(signature)
    }
}

#[async_trait]
impl Container for GuardianContainer {
    async fn start(&self, listen_addr: &str) -> Result<(), ValidatorError> {
        self.is_running.store(true, Ordering::SeqCst);
        let listener = tokio::net::TcpListener::bind(listen_addr).await?;

        let certs_dir = std::env::var("CERTS_DIR").map_err(|_| {
            ValidatorError::Config("CERTS_DIR environment variable must be set".to_string())
        })?;
        let server_config: Arc<ServerConfig> = create_ipc_server_config(
            &format!("{}/ca.pem", certs_dir),
            &format!("{}/guardian-server.pem", certs_dir),
            &format!("{}/guardian-server.key", certs_dir),
        )
        .map_err(|e| ValidatorError::Config(e.to_string()))?;
        let acceptor = TlsAcceptor::from(server_config);

        let orch_channel = self.orchestration_channel.clone();
        let work_channel = self.workload_channel.clone();

        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let acceptor = acceptor.clone();
                let orch_c = orch_channel.clone();
                let work_c = work_channel.clone();
                tokio::spawn(async move {
                    let server_conn = match acceptor.accept(stream).await {
                        Ok(s) => s,
                        Err(e) => return log::error!("[Guardian] TLS accept error: {}", e),
                    };
                    let mut tls_stream = TlsStream::Server(server_conn);

                    let mut kem_ss = match server_post_handshake(
                        &mut tls_stream,
                        ioi_crypto::security::SecurityLevel::Level3,
                    )
                    .await
                    {
                        Ok(ss) => ss,
                        Err(e) => {
                            return log::error!(
                                "[Guardian] Post-quantum key exchange FAILED: {}",
                                e
                            );
                        }
                    };

                    let app_key = match derive_application_key(&tls_stream, &mut kem_ss) {
                        Ok(k) => k,
                        Err(e) => {
                            return log::error!("[Guardian] App key derivation FAILED: {}", e)
                        }
                    };
                    let mut aead_stream = AeadWrappedStream::new(tls_stream, app_key);

                    let mut id_buf = [0u8; 1];
                    match aead_stream.read(&mut id_buf).await {
                        Ok(1) => {
                            let client_id_byte = id_buf[0];
                            log::info!(
                                "[Guardian] Post-quantum channel established for client {}",
                                client_id_byte
                            );
                            match IpcClientType::try_from(client_id_byte) {
                                Ok(IpcClientType::Orchestrator) => {
                                    orch_c.accept_server_connection(aead_stream).await
                                }
                                Ok(IpcClientType::Workload) => {
                                    work_c.accept_server_connection(aead_stream).await
                                }
                                Err(_) => log::warn!(
                                    "[Guardian] Unknown client ID byte: {}",
                                    client_id_byte
                                ),
                            }
                        }
                        Ok(n) => log::warn!(
                            "[Guardian] Expected 1-byte client ID frame, but received {} bytes.",
                            n
                        ),
                        Err(e) => log::error!("[Guardian] Failed to read client ID frame: {}", e),
                    }
                });
            }
        });

        log::info!("Guardian container started and listening.");
        Ok(())
    }

    async fn stop(&self) -> Result<(), ValidatorError> {
        self.is_running.store(false, Ordering::SeqCst);
        log::info!("Guardian container stopped.");
        Ok(())
    }

    fn is_running(&self) -> bool {
        self.is_running.load(Ordering::SeqCst)
    }

    fn id(&self) -> &'static str {
        "guardian"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AttestationSignaturePolicy;
    use futures::stream;
    use ioi_api::crypto::{SerializableKey, SigningKeyPair};
    use ioi_crypto::sign::bls::BlsKeyPair;
    use ioi_crypto::sign::guardian_committee::{
        decode_signers_bitfield, verify_quorum_certificate, verify_witness_certificate,
    };
    use ioi_ipc::control::guardian_control_server::{GuardianControl, GuardianControlServer};
    use ioi_ipc::control::{
        ReportWitnessFaultRequest, ReportWitnessFaultResponse, SecureEgressRequest,
        SecureEgressResponse, SignCommitteeDecisionRequest, SignCommitteeDecisionResponse,
        SignConsensusRequest, SignConsensusResponse, SignWitnessStatementRequest,
        SignWitnessStatementResponse,
    };
    use ioi_types::app::{GuardianProductionMode, KeyAuthorityDescriptor, KeyAuthorityKind};
    use ioi_types::config::{
        GuardianCommitteeConfig, GuardianCommitteeMemberConfig, GuardianTransparencyLogConfig,
        GuardianWitnessCommitteeConfig,
    };
    use rcgen::{BasicConstraints, IsCa};
    use tempfile;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;
    use tokio::time::{sleep, Duration};
    use tokio_rustls::rustls::pki_types::PrivatePkcs8KeyDer;
    use tonic::{transport::Server, Request, Response, Status};

    #[derive(Clone)]
    struct MockRemoteCommitteeSigner {
        member_index: usize,
        signing_key: BlsPrivateKey,
    }

    #[tonic::async_trait]
    impl GuardianControl for MockRemoteCommitteeSigner {
        async fn secure_egress(
            &self,
            _request: Request<SecureEgressRequest>,
        ) -> Result<Response<SecureEgressResponse>, Status> {
            Err(Status::unimplemented("unused in remote committee tests"))
        }

        async fn sign_consensus(
            &self,
            _request: Request<SignConsensusRequest>,
        ) -> Result<Response<SignConsensusResponse>, Status> {
            Err(Status::unimplemented("unused in remote committee tests"))
        }

        async fn sign_committee_decision(
            &self,
            request: Request<SignCommitteeDecisionRequest>,
        ) -> Result<Response<SignCommitteeDecisionResponse>, Status> {
            let request = request.into_inner();
            let decision: GuardianDecision = codec::from_bytes_canonical(&request.decision)
                .map_err(|e| Status::invalid_argument(format!("invalid decision payload: {e}")))?;
            let decision_hash =
                canonical_decision_hash(&decision).map_err(|e| Status::internal(e.to_string()))?;
            let signature = self
                .signing_key
                .sign(&decision_hash)
                .map_err(|e| Status::internal(e.to_string()))?;
            let member_index = u32::try_from(self.member_index)
                .map_err(|_| Status::internal("member index overflow"))?;

            Ok(Response::new(SignCommitteeDecisionResponse {
                manifest_hash: request.manifest_hash,
                decision_hash: decision_hash.to_vec(),
                partial_signatures: vec![GuardianMemberSignature {
                    member_index,
                    signature: signature.to_bytes(),
                }],
            }))
        }

        async fn sign_witness_statement(
            &self,
            _request: Request<SignWitnessStatementRequest>,
        ) -> Result<Response<SignWitnessStatementResponse>, Status> {
            Err(Status::unimplemented("unused in remote committee tests"))
        }

        async fn report_witness_fault(
            &self,
            _request: Request<ReportWitnessFaultRequest>,
        ) -> Result<Response<ReportWitnessFaultResponse>, Status> {
            Err(Status::unimplemented("unused in remote committee tests"))
        }
    }

    async fn spawn_mock_remote_committee_server(
        service: MockRemoteCommitteeSigner,
    ) -> (String, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let incoming = stream::unfold(listener, |listener| async move {
            match listener.accept().await {
                Ok((stream, _)) => Some((Ok::<_, std::io::Error>(stream), listener)),
                Err(error) => Some((Err(error), listener)),
            }
        });
        let handle = tokio::spawn(async move {
            Server::builder()
                .add_service(GuardianControlServer::new(service))
                .serve_with_incoming(incoming)
                .await
                .unwrap();
        });
        sleep(Duration::from_millis(50)).await;
        (format!("http://{addr}"), handle)
    }

    async fn read_http_request<S>(stream: &mut S) -> Result<Vec<u8>>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let mut buffer = Vec::new();
        let mut chunk = [0u8; 1024];
        let mut expected_total_len = None;

        loop {
            let read = stream.read(&mut chunk).await?;
            if read == 0 {
                break;
            }
            buffer.extend_from_slice(&chunk[..read]);
            if let Some(header_end) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
                let header_end = header_end + 4;
                if expected_total_len.is_none() {
                    let headers = String::from_utf8_lossy(&buffer[..header_end]);
                    let content_length = headers
                        .lines()
                        .find_map(|line| {
                            let (name, value) = line.split_once(':')?;
                            if name.eq_ignore_ascii_case("content-length") {
                                value.trim().parse::<usize>().ok()
                            } else {
                                None
                            }
                        })
                        .unwrap_or(0);
                    expected_total_len = Some(header_end + content_length);
                }
                if buffer.len() >= expected_total_len.unwrap_or(header_end) {
                    return Ok(buffer);
                }
            }
        }

        Err(anyhow!("incomplete HTTP request"))
    }

    async fn spawn_tls_test_server(
        tempdir: &tempfile::TempDir,
    ) -> Result<(u16, String, [u8; 32], tokio::task::JoinHandle<()>)> {
        let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();

        let mut ca_params = CertificateParams::new(vec!["IOI Test CA".to_string()])?;
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let ca_keypair = KeyPair::generate()?;
        let ca_cert = ca_params.self_signed(&ca_keypair)?;
        let ca_pem_path = tempdir.path().join("test-ca.pem");
        std::fs::write(&ca_pem_path, ca_cert.pem())?;

        let mut server_params = CertificateParams::new(vec!["localhost".to_string()])?;
        server_params.subject_alt_names = vec![SanType::DnsName(
            Ia5String::try_from("localhost".to_string()).unwrap(),
        )];
        let server_keypair = KeyPair::generate()?;
        let server_cert = server_params.signed_by(&server_keypair, &ca_cert, &ca_keypair)?;
        let leaf_hash =
            digest_to_array(Sha256::digest(server_cert.der().as_ref()).map_err(|e| anyhow!(e))?)?;
        let cert_chain = vec![server_cert.der().clone()];
        let private_key = PrivatePkcs8KeyDer::from(server_keypair.serialize_der());
        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain, private_key.into())?;

        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        let acceptor = TlsAcceptor::from(Arc::new(server_config));
        let handle = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut tls_stream = acceptor.accept(stream).await.unwrap();
            let _request = read_http_request(&mut tls_stream).await.unwrap();
            tls_stream
                .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok")
                .await
                .unwrap();
            let _ = tls_stream.shutdown().await;
        });

        Ok((port, ca_pem_path.display().to_string(), leaf_hash, handle))
    }

    #[test]
    fn test_no_plaintext_at_rest() {
        let seed = [0xAAu8; 32]; // Distinct pattern to search for
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("guardian.key");

        // Mock the environment variable for passphrase
        unsafe { std::env::set_var("IOI_GUARDIAN_KEY_PASS", "test_pass") };

        // Write key using the new atomic save_encrypted_file
        GuardianContainer::save_encrypted_file(&path, &seed).expect("Save failed");

        // Verify file exists
        assert!(path.exists());

        // Read raw file content
        let content = std::fs::read(&path).expect("Read failed");

        // 1. Verify Magic Header
        assert_eq!(&content[0..8], b"IOI-GKEY", "Header mismatch");

        // 2. Scan entire file to ensure the raw seed pattern does not appear
        assert!(
            content.windows(32).all(|window| window != seed),
            "Plaintext seed found on disk! Encryption failed."
        );

        // 3. Verify we can decrypt it back
        let loaded = GuardianContainer::load_encrypted_file(&path).expect("Load failed");
        assert_eq!(loaded, seed.to_vec(), "Roundtrip mismatch");
    }

    #[tokio::test]
    async fn guardian_slot_lock_rejects_conflicting_payloads_for_same_slot() {
        let dir = tempfile::tempdir().unwrap();
        let mut members = Vec::new();
        for index in 0..3 {
            let keypair = BlsKeyPair::generate().unwrap();
            let private_key_path = dir.path().join(format!("member-{index}.bls"));
            std::fs::write(
                &private_key_path,
                hex::encode(keypair.private_key().to_bytes()),
            )
            .unwrap();
            members.push(GuardianCommitteeMemberConfig {
                member_id: format!("member-{index}"),
                endpoint: None,
                public_key: keypair.public_key().to_bytes(),
                private_key_path: Some(private_key_path.display().to_string()),
                provider: Some(format!("provider-{index}")),
                region: Some(format!("region-{}", index % 2)),
                host_class: Some(format!("host-{index}")),
                key_authority_kind: Some(KeyAuthorityKind::CloudKms),
            });
        }

        let config = GuardianConfig {
            signature_policy: AttestationSignaturePolicy::Fixed,
            production_mode: GuardianProductionMode::Development,
            key_authority: Some(KeyAuthorityDescriptor {
                kind: KeyAuthorityKind::DevMemory,
                ..Default::default()
            }),
            committee: GuardianCommitteeConfig {
                threshold: 2,
                members,
                transparency_log_id: "guardian-test".into(),
            },
            experimental_witness_committees: Vec::new(),
            hardening: Default::default(),
            transparency_log: GuardianTransparencyLogConfig {
                log_id: "guardian-test".into(),
                endpoint: None,
                signing_key_path: None,
                required: false,
            },
            verifier_policy: Default::default(),
            enforce_binary_integrity: false,
            approved_orchestrator_hash: None,
            approved_workload_hash: None,
            binary_dir_override: None,
        };
        let validator_account_id = AccountId([9u8; 32]);
        let container =
            GuardianContainer::new(dir.path().to_path_buf(), config, validator_account_id).unwrap();
        let signer = libp2p::identity::Keypair::generate_ed25519();

        let first_bundle = container
            .sign_consensus_with_guardian(
                &signer,
                [1u8; 32],
                42,
                7,
                validator_account_id.0.to_vec(),
                0,
                [0u8; 32],
                None,
                None,
                None,
                None,
                0,
            )
            .await
            .unwrap();
        assert!(first_bundle.guardian_certificate.is_some());

        let err = container
            .sign_consensus_with_guardian(
                &signer,
                [2u8; 32],
                42,
                7,
                validator_account_id.0.to_vec(),
                first_bundle.counter,
                first_bundle.trace_hash,
                None,
                None,
                None,
                None,
                0,
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("slot already certified"));
    }

    #[tokio::test]
    async fn guardian_committee_collects_remote_partial_signatures() {
        let remote_key = BlsKeyPair::generate().unwrap();
        let (remote_endpoint, server_handle) =
            spawn_mock_remote_committee_server(MockRemoteCommitteeSigner {
                member_index: 1,
                signing_key: remote_key.private_key(),
            })
            .await;

        let dir = tempfile::tempdir().unwrap();
        let local_key = BlsKeyPair::generate().unwrap();
        let local_private_key_path = dir.path().join("member-0.bls");
        std::fs::write(
            &local_private_key_path,
            hex::encode(local_key.private_key().to_bytes()),
        )
        .unwrap();

        let members = vec![
            GuardianCommitteeMemberConfig {
                member_id: "member-0".into(),
                endpoint: None,
                public_key: local_key.public_key().to_bytes(),
                private_key_path: Some(local_private_key_path.display().to_string()),
                provider: Some("provider-a".into()),
                region: Some("us-east-1".into()),
                host_class: Some("host-a".into()),
                key_authority_kind: Some(KeyAuthorityKind::CloudKms),
            },
            GuardianCommitteeMemberConfig {
                member_id: "member-1".into(),
                endpoint: Some(remote_endpoint.clone()),
                public_key: remote_key.public_key().to_bytes(),
                private_key_path: None,
                provider: Some("provider-b".into()),
                region: Some("us-west-2".into()),
                host_class: Some("host-b".into()),
                key_authority_kind: Some(KeyAuthorityKind::Tpm2),
            },
        ];
        let config = GuardianConfig {
            signature_policy: AttestationSignaturePolicy::Fixed,
            production_mode: GuardianProductionMode::Development,
            key_authority: Some(KeyAuthorityDescriptor {
                kind: KeyAuthorityKind::DevMemory,
                ..Default::default()
            }),
            committee: GuardianCommitteeConfig {
                threshold: 2,
                members,
                transparency_log_id: "guardian-test".into(),
            },
            experimental_witness_committees: Vec::new(),
            hardening: Default::default(),
            transparency_log: GuardianTransparencyLogConfig {
                log_id: "guardian-test".into(),
                endpoint: None,
                signing_key_path: None,
                required: false,
            },
            verifier_policy: Default::default(),
            enforce_binary_integrity: false,
            approved_orchestrator_hash: None,
            approved_workload_hash: None,
            binary_dir_override: None,
        };
        let validator_account_id = AccountId([5u8; 32]);
        let committee_client = GuardianCommitteeClient::from_config(&config, validator_account_id)
            .unwrap()
            .unwrap();
        let container =
            GuardianContainer::new(dir.path().to_path_buf(), config, validator_account_id).unwrap();
        let signer = libp2p::identity::Keypair::generate_ed25519();
        let payload_hash = [9u8; 32];

        let bundle = container
            .sign_consensus_with_guardian(
                &signer,
                payload_hash,
                17,
                3,
                validator_account_id.0.to_vec(),
                0,
                [0u8; 32],
                None,
                None,
                None,
                None,
                0,
            )
            .await
            .unwrap();
        let certificate = bundle.guardian_certificate.clone().unwrap();
        let signer_indexes = decode_signers_bitfield(
            committee_client.manifest.members.len(),
            &certificate.signers_bitfield,
        )
        .unwrap();
        assert_eq!(signer_indexes, vec![0, 1]);

        let decision = GuardianDecision {
            domain: GuardianDecisionDomain::ConsensusSlot as u8,
            subject: validator_account_id.0.to_vec(),
            payload_hash,
            counter: certificate.counter,
            trace_hash: certificate.trace_hash,
            measurement_root: certificate.measurement_root,
            policy_hash: committee_client.default_policy_hash(),
        };
        verify_quorum_certificate(&committee_client.manifest, &decision, &certificate).unwrap();

        server_handle.abort();
    }

    #[tokio::test]
    async fn guardian_sign_consensus_issues_experimental_witness_certificate() {
        let dir = tempfile::tempdir().unwrap();

        let mut guardian_members = Vec::new();
        for index in 0..3 {
            let keypair = BlsKeyPair::generate().unwrap();
            let private_key_path = dir.path().join(format!("guardian-member-{index}.bls"));
            std::fs::write(
                &private_key_path,
                hex::encode(keypair.private_key().to_bytes()),
            )
            .unwrap();
            guardian_members.push(GuardianCommitteeMemberConfig {
                member_id: format!("guardian-{index}"),
                endpoint: None,
                public_key: keypair.public_key().to_bytes(),
                private_key_path: Some(private_key_path.display().to_string()),
                provider: Some(format!("provider-{index}")),
                region: Some(format!("region-{index}")),
                host_class: Some(format!("host-{index}")),
                key_authority_kind: Some(KeyAuthorityKind::CloudKms),
            });
        }

        let mut witness_members = Vec::new();
        for index in 0..3 {
            let keypair = BlsKeyPair::generate().unwrap();
            let private_key_path = dir.path().join(format!("witness-member-{index}.bls"));
            std::fs::write(
                &private_key_path,
                hex::encode(keypair.private_key().to_bytes()),
            )
            .unwrap();
            witness_members.push(GuardianCommitteeMemberConfig {
                member_id: format!("witness-{index}"),
                endpoint: None,
                public_key: keypair.public_key().to_bytes(),
                private_key_path: Some(private_key_path.display().to_string()),
                provider: Some(format!("witness-provider-{index}")),
                region: Some(format!("witness-region-{index}")),
                host_class: Some(format!("witness-host-{index}")),
                key_authority_kind: Some(KeyAuthorityKind::Tpm2),
            });
        }

        let config = GuardianConfig {
            signature_policy: AttestationSignaturePolicy::Fixed,
            production_mode: GuardianProductionMode::Development,
            key_authority: Some(KeyAuthorityDescriptor {
                kind: KeyAuthorityKind::DevMemory,
                ..Default::default()
            }),
            committee: GuardianCommitteeConfig {
                threshold: 2,
                members: guardian_members,
                transparency_log_id: "guardian-test".into(),
            },
            experimental_witness_committees: vec![GuardianWitnessCommitteeConfig {
                committee_id: "witness-a".into(),
                epoch: 7,
                threshold: 2,
                members: witness_members,
                transparency_log_id: "witness-test".into(),
                policy_hash: Some([0x77u8; 32]),
            }],
            hardening: Default::default(),
            transparency_log: GuardianTransparencyLogConfig {
                log_id: "guardian-test".into(),
                endpoint: None,
                signing_key_path: None,
                required: false,
            },
            verifier_policy: Default::default(),
            enforce_binary_integrity: false,
            approved_orchestrator_hash: None,
            approved_workload_hash: None,
            binary_dir_override: None,
        };

        let validator_account_id = AccountId([7u8; 32]);
        let witness_clients = GuardianWitnessCommitteeClient::from_configs(&config).unwrap();
        let (&witness_manifest_hash, witness_client) = witness_clients.iter().next().unwrap();
        let container =
            GuardianContainer::new(dir.path().to_path_buf(), config, validator_account_id).unwrap();
        let signer = libp2p::identity::Keypair::generate_ed25519();
        let payload_hash = [0x42u8; 32];

        let bundle = container
            .sign_consensus_with_guardian(
                &signer,
                payload_hash,
                21,
                4,
                validator_account_id.0.to_vec(),
                0,
                [0u8; 32],
                None,
                None,
                None,
                Some(witness_manifest_hash),
                0,
            )
            .await
            .unwrap();

        let guardian_certificate = bundle.guardian_certificate.unwrap();
        let witness_certificate = guardian_certificate
            .experimental_witness_certificate
            .clone()
            .expect("expected experimental witness certificate");
        assert_eq!(witness_certificate.manifest_hash, witness_manifest_hash);
        assert_eq!(witness_certificate.reassignment_depth, 0);
        assert!(witness_certificate.log_checkpoint.is_some());

        let statement = GuardianWitnessStatement {
            producer_account_id: validator_account_id,
            height: 21,
            view: 4,
            guardian_manifest_hash: guardian_certificate.manifest_hash,
            guardian_decision_hash: guardian_certificate.decision_hash,
            guardian_counter: guardian_certificate.counter,
            guardian_trace_hash: guardian_certificate.trace_hash,
            guardian_measurement_root: guardian_certificate.measurement_root,
            guardian_checkpoint_root: guardian_certificate
                .log_checkpoint
                .as_ref()
                .map(|checkpoint| checkpoint.root_hash)
                .unwrap_or([0u8; 32]),
        };
        verify_witness_certificate(&witness_client.manifest, &statement, &witness_certificate)
            .unwrap();
    }

    #[tokio::test]
    async fn notarized_https_request_enforces_tls_policy_and_hashes_peer_chain() {
        let tempdir = tempfile::tempdir().unwrap();
        let (port, ca_pem_path, leaf_hash, server_handle) =
            spawn_tls_test_server(&tempdir).await.unwrap();
        let policy = GuardianVerifierPolicyConfig {
            tls_allowed_server_names: vec!["localhost".into()],
            tls_allowed_root_pem_paths: vec![ca_pem_path],
            tls_pinned_leaf_certificate_sha256: vec![hex::encode(leaf_hash)],
            tls_transcript_version: 1,
            ..Default::default()
        };

        let (
            response_bytes,
            server_name,
            chain_hash,
            returned_leaf_hash,
            handshake_hash,
            request_hash,
            response_hash,
        ) = notarized_https_request(
            &format!("localhost:{port}"),
            "/v1/test",
            "POST",
            br#"{"ping":"pong"}"#.to_vec(),
            Vec::new(),
            &policy,
        )
        .await
        .unwrap();

        assert_eq!(response_bytes, b"ok");
        assert_eq!(server_name, "localhost");
        assert_ne!(chain_hash, [0u8; 32]);
        assert_eq!(returned_leaf_hash, leaf_hash);
        assert_ne!(handshake_hash, [0u8; 32]);
        assert_ne!(request_hash, [0u8; 32]);
        assert_ne!(response_hash, [0u8; 32]);

        server_handle.abort();
    }

    #[tokio::test]
    async fn notarized_https_request_rejects_server_name_policy_mismatch() {
        let tempdir = tempfile::tempdir().unwrap();
        let (port, ca_pem_path, _, server_handle) = spawn_tls_test_server(&tempdir).await.unwrap();
        let policy = GuardianVerifierPolicyConfig {
            tls_allowed_server_names: vec!["example.com".into()],
            tls_allowed_root_pem_paths: vec![ca_pem_path],
            tls_pinned_leaf_certificate_sha256: Vec::new(),
            tls_transcript_version: 1,
            ..Default::default()
        };

        let err = notarized_https_request(
            &format!("localhost:{port}"),
            "/v1/test",
            "POST",
            br#"{}"#.to_vec(),
            Vec::new(),
            &policy,
        )
        .await
        .unwrap_err();
        assert!(err
            .to_string()
            .contains("is not allowed by verifier policy"));

        server_handle.abort();
    }

    #[tokio::test]
    async fn notarized_https_request_rejects_leaf_pin_mismatch() {
        let tempdir = tempfile::tempdir().unwrap();
        let (port, ca_pem_path, _, server_handle) = spawn_tls_test_server(&tempdir).await.unwrap();
        let policy = GuardianVerifierPolicyConfig {
            tls_allowed_server_names: vec!["localhost".into()],
            tls_allowed_root_pem_paths: vec![ca_pem_path],
            tls_pinned_leaf_certificate_sha256: vec![hex::encode([0xAAu8; 32])],
            tls_transcript_version: 1,
            ..Default::default()
        };

        let err = notarized_https_request(
            &format!("localhost:{port}"),
            "/v1/test",
            "POST",
            br#"{}"#.to_vec(),
            Vec::new(),
            &policy,
        )
        .await
        .unwrap_err();
        assert!(err
            .to_string()
            .contains("does not match any configured TLS pin"));

        server_handle.abort();
    }

    #[tokio::test]
    async fn notarized_https_request_rejects_hostname_mismatch() {
        let tempdir = tempfile::tempdir().unwrap();
        let (port, ca_pem_path, leaf_hash, server_handle) =
            spawn_tls_test_server(&tempdir).await.unwrap();
        let policy = GuardianVerifierPolicyConfig {
            tls_allowed_server_names: vec!["127.0.0.1".into()],
            tls_allowed_root_pem_paths: vec![ca_pem_path],
            tls_pinned_leaf_certificate_sha256: vec![hex::encode(leaf_hash)],
            tls_transcript_version: 1,
            ..Default::default()
        };

        let err = notarized_https_request(
            &format!("127.0.0.1:{port}"),
            "/v1/test",
            "POST",
            br#"{}"#.to_vec(),
            Vec::new(),
            &policy,
        )
        .await
        .unwrap_err();
        assert!(!err.to_string().is_empty());

        server_handle.abort();
    }
}
