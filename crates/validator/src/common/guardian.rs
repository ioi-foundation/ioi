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
    LoadAssignedRecoveryShareRequest, ObserveAsymptoteRequest, ReportWitnessFaultRequest,
    SealConsensusRequest, SignCommitteeDecisionRequest, SignConsensusRequest,
    SignWitnessStatementRequest,
};
use ioi_ipc::IpcClientType;
use ioi_types::app::{
    account_id_from_key_material, build_http_egress_seal_object,
    canonical_asymptote_observer_assignment_hash, canonical_asymptote_observer_assignments_hash,
    canonical_asymptote_observer_challenges_hash,
    canonical_asymptote_observer_observation_request_hash,
    canonical_asymptote_observer_transcript_hash, canonical_asymptote_observer_transcripts_hash,
    canonical_collapse_hash_for_sealed_effect, sealed_finality_proof_observer_binding,
    verify_seal_object, AccountId, AssignedRecoveryShareEnvelopeV1,
    AsymptoteObserverCanonicalAbort, AsymptoteObserverCanonicalClose, AsymptoteObserverCertificate,
    AsymptoteObserverChallenge, AsymptoteObserverChallengeCommitment,
    AsymptoteObserverChallengeKind, AsymptoteObserverCloseCertificate,
    AsymptoteObserverObservation, AsymptoteObserverObservationRequest, AsymptoteObserverPlanEntry,
    AsymptoteObserverSealingMode, AsymptoteObserverStatement, AsymptoteObserverTranscript,
    AsymptoteObserverTranscriptCommitment, AsymptotePolicy, BinaryMeasurement, BootAttestation,
    CanonicalCollapseObject, CollapseState, EgressReceipt, FinalityTier, GuardianCommitteeManifest,
    GuardianCommitteeMember, GuardianDecision, GuardianDecisionDomain, GuardianLogCheckpoint,
    GuardianProductionMode, GuardianQuorumCertificate, GuardianWitnessCertificate,
    GuardianWitnessCommitteeManifest, GuardianWitnessFaultEvidence, GuardianWitnessRecoveryBinding,
    GuardianWitnessRecoveryBindingAssignment, GuardianWitnessStatement, RecoveryShareMaterial,
    SealObject, SealedFinalityProof, SignatureBundle, SignatureProof, SignatureSuite,
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

include!("guardian/types.rs");
include!("guardian/support.rs");
include!("guardian/signing.rs");
include!("guardian/runtime.rs");
include!("guardian/server.rs");
