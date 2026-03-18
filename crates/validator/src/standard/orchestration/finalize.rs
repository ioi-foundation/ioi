// Path: crates/validator/src/standard/orchestration/finalize.rs

use super::aft_collapse::{
    derive_expected_aft_canonical_collapse_for_block,
    require_persisted_aft_canonical_collapse_if_needed,
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
        account_id_from_key_material,
        build_committed_surface_canonical_order_certificate,
        canonical_asymptote_observer_assignments_hash,
        canonical_asymptote_observer_canonical_close_hash,
        canonical_asymptote_observer_challenges_hash,
        canonical_asymptote_observer_transcripts_hash,
        canonical_sealed_finality_proof_signing_bytes,
        derive_asymptote_observer_plan_entries, derive_guardian_witness_assignment,
        derive_canonical_order_execution_object,
        derive_guardian_witness_assignments_for_strata,
        effective_set_for_height,
        guardian_registry_asymptote_policy_key, guardian_registry_committee_account_key,
        guardian_registry_committee_key, guardian_registry_witness_key,
        guardian_registry_witness_seed_key, guardian_registry_witness_set_key, read_validator_sets,
        to_root_hash, AccountId,
        AsymptoteObserverCanonicalAbort,
        AsymptoteObserverCanonicalClose,
        AsymptoteObserverChallenge, AsymptoteObserverChallengeCommitment,
        AsymptoteObserverChallengeKind,
        AsymptoteObserverSealingMode, AsymptoteObserverStatement,
        AsymptoteObserverTranscript, AsymptoteObserverTranscriptCommitment, AsymptotePolicy, Block,
        BlockHeader,
        CanonicalCollapseObject, CanonicalOrderAbort, CanonicalOrderExecutionObject,
        CanonicalOrderPublicationBundle,
        ChainTransaction,
        ConsensusVote, GuardianCommitteeManifest, GuardianLogCheckpoint,
        GuardianWitnessCommitteeManifest, GuardianWitnessEpochSeed, GuardianWitnessFaultEvidence,
        GuardianWitnessFaultKind, GuardianWitnessSet, SealedFinalityProof, SignHeader,
        SignatureBundle, SignatureProof, SignatureSuite, StateEntry, SystemPayload,
        SystemTransaction,
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
    canonical_abort: Option<CanonicalOrderAbort>,
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
        return Some(
            "canonical observer close was carried on a non-SealedFinal proof path".into(),
        );
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
        let nonce = reserve_nonce_for_account(&self.workload_client, &self.nonce_manager, account_id)
            .await;
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
                let invalid_close_challenge =
                    build_invalid_canonical_close_challenge(
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
    let transcript_count =
        u16::try_from(transcripts.len()).map_err(|_| anyhow!("observer transcript count exceeds u16"))?;
    let challenge_count =
        u16::try_from(challenges.len()).map_err(|_| anyhow!("observer challenge count exceeds u16"))?;
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
    let sign_bytes = canonical_sealed_finality_proof_signing_bytes(proof).map_err(anyhow::Error::msg)?;
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
            codec::to_bytes_canonical(&artifacts.challenge_commitment)
                .map_err(|e| anyhow!(e))?,
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
            canonical_abort: None,
        }),
        Err(canonical_abort) => Ok(CanonicalOrderPublicationArtifacts {
            bundle: None,
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
            }
        }
        let publisher = GuardianRegistryPublisher::from_context(context_arc).await;
        let artifacts =
            build_canonical_order_publication_artifacts(&final_block.header, &final_block.transactions)?;
        publish_canonical_order_artifacts(&publisher, &artifacts).await?;
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
        let accepted = engine.observe_committed_block(&final_block.header, committed_collapse.as_ref());
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
        match signer
            .sign_consensus_payload(
                preimage_hash,
                final_block.header.height,
                final_block.header.view,
                Some((assignment.manifest_hash, reassignment_depth)),
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
    let witness_manifest_hashes = if observer_plan.is_empty() {
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
        derive_guardian_witness_assignments_for_strata(
            &witness_seed,
            &witness_set,
            &witness_manifests,
            sealed_block.header.producer_account_id,
            sealed_block.header.height,
            sealed_block.header.view,
            0,
            &policy.required_witness_strata,
        )
        .map_err(|e| anyhow!(e))?
        .iter()
        .map(|assignment| assignment.manifest_hash)
        .collect()
    } else {
        Vec::new()
    };
    let preimage_hash =
        ioi_crypto::algorithms::hash::sha256(&sealed_block.header.to_preimage_for_signing()?)?;
    let mut sealed_finality_proof = signer
        .seal_consensus_payload(
            preimage_hash,
            sealed_block.header.height,
            sealed_block.header.view,
            witness_manifest_hashes,
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
    let canonical_collapse_object = derive_expected_aft_canonical_collapse_for_block(
        view_resolver.workload_client().as_ref(),
        &sealed_block,
    )
    .await?
    .ok_or_else(|| anyhow!("failed to derive canonical collapse object for sealed block publication"))?;
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
        ChainId, GuardianQuorumCertificate, QuorumCertificate, StateAnchor, StateRoot,
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
            signature: vec![5],
        }
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

        let artifacts = canonicalize_observer_sealed_finality_proof(
            &header,
            &policy,
            [64u8; 32],
            &mut proof,
        )
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
        let challenges_root =
            canonical_asymptote_observer_challenges_hash(&[challenge.clone()]).expect("challenge root");
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

        let methods = selected
            .into_iter()
            .map(|tx| match tx {
                ChainTransaction::System(system_tx) => match system_tx.payload {
                    SystemPayload::CallService {
                        service_id,
                        method,
                        ..
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
        let ordered_transactions = ioi_types::app::canonicalize_transactions_for_header(
            &base_header,
            &[tx_one, tx_two],
        )
        .expect("canonicalized transactions");
        let tx_hashes: Vec<[u8; 32]> = ordered_transactions
            .iter()
            .map(|tx| tx.hash().expect("tx hash"))
            .collect();

        let mut header = base_header;
        header.transactions_root = ioi_types::app::canonical_transaction_root_from_hashes(
            &tx_hashes,
        )
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

        let methods = selected
            .into_iter()
            .map(|tx| match tx {
                ChainTransaction::System(system_tx) => match system_tx.payload {
                    SystemPayload::CallService {
                        service_id,
                        method,
                        ..
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
            vec!["publish_aft_canonical_order_artifact_bundle@v1".to_string()]
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
                        service_id,
                        method,
                        ..
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
        let ordered_transactions = ioi_types::app::canonicalize_transactions_for_header(
            &base_header,
            &[tx_one, tx_two],
        )
        .expect("canonicalized transactions");
        let tx_hashes: Vec<[u8; 32]> = ordered_transactions
            .iter()
            .map(|tx| tx.hash().expect("tx hash"))
            .collect();

        let mut header = base_header;
        header.transactions_root = ioi_types::app::canonical_transaction_root_from_hashes(
            &tx_hashes,
        )
        .expect("transactions root");
        header.canonical_order_certificate = Some(
            build_committed_surface_canonical_order_certificate(&header, &ordered_transactions)
                .expect("build committed-surface certificate"),
        );
        let collapse = ioi_types::app::derive_canonical_collapse_object(&header, &ordered_transactions)
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
                        service_id,
                        method,
                        ..
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
