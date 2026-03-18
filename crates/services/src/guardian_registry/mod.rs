use async_trait::async_trait;
use ioi_api::services::{BlockchainService, UpgradableService};
use ioi_api::state::StateAccess;
use ioi_api::transaction::context::TxContext;
use ioi_crypto::algorithms::hash::sha256;
use ioi_types::app::{
    aft_bulletin_availability_certificate_key, aft_bulletin_commitment_key,
    aft_canonical_bulletin_close_key, aft_canonical_collapse_object_key,
    aft_canonical_order_abort_key,
    aft_bulletin_entry_key, aft_omission_proof_key, aft_order_certificate_key, evidence_id,
    bind_canonical_collapse_continuity,
    canonical_asymptote_observer_assignment_hash,
    canonical_asymptote_observer_canonical_abort_hash,
    canonical_asymptote_observer_canonical_close_hash,
    canonical_asymptote_observer_challenges_hash,
    canonical_asymptote_observer_observation_request_hash,
    canonical_asymptote_observer_transcript_hash,
    canonical_bulletin_availability_certificate_hash,
    canonical_bulletin_close_hash,
    canonical_bulletin_commitment_hash,
    canonical_order_certificate_hash,
    extract_canonical_bulletin_surface, verify_canonical_collapse_continuity,
    verify_canonical_order_publication_bundle,
    effective_set_for_height,
    guardian_registry_asymptote_policy_key, guardian_registry_committee_account_key,
    guardian_registry_committee_key, guardian_registry_effect_nullifier_key,
    guardian_registry_effect_verifier_key, guardian_registry_log_key,
    guardian_registry_observer_canonical_abort_key,
    guardian_registry_observer_canonical_close_key,
    guardian_registry_observer_challenge_commitment_key,
    guardian_registry_observer_challenge_key, guardian_registry_observer_transcript_commitment_key,
    guardian_registry_observer_transcript_key,
    guardian_registry_sealed_effect_key, guardian_registry_witness_fault_key,
    guardian_registry_witness_key, guardian_registry_witness_seed_key,
    guardian_registry_witness_set_key, read_validator_sets, write_validator_sets, AccountId,
    AsymptoteObserverCanonicalAbort,
    AsymptoteObserverCanonicalClose,
    AsymptoteObserverChallenge, AsymptoteObserverChallengeCommitment,
    AsymptoteObserverChallengeKind,
    AsymptoteObserverSealingMode, AsymptoteObserverTranscript,
    AsymptoteObserverTranscriptCommitment, AsymptotePolicy, BulletinAvailabilityCertificate,
    BulletinCommitment, BulletinSurfaceEntry, CanonicalBulletinClose,
    CanonicalCollapseKind, CanonicalCollapseObject, CanonicalOrderAbort,
    CanonicalOrderAbortReason, CanonicalOrderCertificate, CanonicalOrderPublicationBundle,
    CollapseState, FinalityTier,
    EffectProofVerifierDescriptor, FailureReport, GuardianCommitteeManifest, GuardianLogCheckpoint,
    GuardianMeasurementProfile, GuardianTransparencyLogDescriptor, GuardianWitnessCommitteeManifest,
    GuardianWitnessEpochSeed, GuardianWitnessFaultEvidence, GuardianWitnessSet, OffenseFacts,
    OffenseType, OmissionProof, ProofOfDivergence, SealedEffectRecord,
    AFT_BULLETIN_ENTRY_PREFIX,
    GUARDIAN_REGISTRY_CHECKPOINT_PREFIX, GUARDIAN_REGISTRY_EQUIVOCATION_PREFIX,
    GUARDIAN_REGISTRY_MEASUREMENT_PREFIX,
    GUARDIAN_REGISTRY_OBSERVER_CHALLENGE_PREFIX,
};
use ioi_types::codec;
use ioi_types::config::GuardianRegistryParams;
use ioi_types::error::{StateError, TransactionError, UpgradeError};
use ioi_types::keys::{EVIDENCE_REGISTRY_KEY, QUARANTINED_VALIDATORS_KEY, VALIDATOR_SET_KEY};
use ioi_types::service_configs::Capabilities;
use std::any::Any;
use std::collections::BTreeSet;
use tracing::warn;

#[derive(Debug, Clone)]
pub struct GuardianRegistry {
    pub config: GuardianRegistryParams,
}

impl GuardianRegistry {
    pub fn new(config: GuardianRegistryParams) -> Self {
        Self { config }
    }

    pub fn manifest_hash(
        manifest: &GuardianCommitteeManifest,
    ) -> Result<[u8; 32], TransactionError> {
        let bytes = codec::to_bytes_canonical(manifest).map_err(TransactionError::Serialization)?;
        sha256(&bytes)
            .map_err(|e| TransactionError::Invalid(e.to_string()))
            .and_then(|digest| {
                digest
                    .try_into()
                    .map_err(|_| TransactionError::Invalid("invalid manifest hash length".into()))
            })
    }

    pub fn load_manifest_by_hash(
        state: &dyn StateAccess,
        manifest_hash: &[u8; 32],
    ) -> Result<Option<GuardianCommitteeManifest>, StateError> {
        let key = guardian_registry_committee_key(manifest_hash);
        match state.get(&key)? {
            Some(bytes) => codec::from_bytes_canonical(&bytes)
                .map(Some)
                .map_err(|e| StateError::InvalidValue(e.to_string())),
            None => Ok(None),
        }
    }

    pub fn load_manifest_hash_by_account(
        state: &dyn StateAccess,
        account_id: &AccountId,
    ) -> Result<Option<[u8; 32]>, StateError> {
        let key = guardian_registry_committee_account_key(account_id);
        match state.get(&key)? {
            Some(bytes) => bytes
                .as_slice()
                .try_into()
                .map(Some)
                .map_err(|_| StateError::InvalidValue("invalid guardian manifest hash".into())),
            None => Ok(None),
        }
    }

    pub fn load_witness_manifest_by_hash(
        state: &dyn StateAccess,
        manifest_hash: &[u8; 32],
    ) -> Result<Option<GuardianWitnessCommitteeManifest>, StateError> {
        let key = guardian_registry_witness_key(manifest_hash);
        match state.get(&key)? {
            Some(bytes) => codec::from_bytes_canonical(&bytes)
                .map(Some)
                .map_err(|e| StateError::InvalidValue(e.to_string())),
            None => Ok(None),
        }
    }

    pub fn profile_allows_measurement(
        state: &dyn StateAccess,
        measurement_root: &[u8; 32],
    ) -> Result<bool, StateError> {
        let Some(profile_bytes) =
            state.get(&[GUARDIAN_REGISTRY_MEASUREMENT_PREFIX, b"default"].concat())?
        else {
            return Ok(false);
        };
        let profile: GuardianMeasurementProfile = codec::from_bytes_canonical(&profile_bytes)
            .map_err(|e| StateError::InvalidValue(e.to_string()))?;
        Ok(profile
            .allowed_measurement_roots
            .iter()
            .any(|root| root == measurement_root))
    }

    pub fn load_asymptote_policy(
        state: &dyn StateAccess,
        epoch: u64,
    ) -> Result<Option<AsymptotePolicy>, StateError> {
        match state.get(&guardian_registry_asymptote_policy_key(epoch))? {
            Some(bytes) => codec::from_bytes_canonical(&bytes)
                .map(Some)
                .map_err(|e| StateError::InvalidValue(e.to_string())),
            None => Ok(None),
        }
    }

    pub fn load_bulletin_commitment(
        state: &dyn StateAccess,
        height: u64,
    ) -> Result<Option<BulletinCommitment>, StateError> {
        match state.get(&aft_bulletin_commitment_key(height))? {
            Some(bytes) => codec::from_bytes_canonical(&bytes)
                .map(Some)
                .map_err(|e| StateError::InvalidValue(e.to_string())),
            None => Ok(None),
        }
    }

    pub fn load_bulletin_surface_entries(
        state: &dyn StateAccess,
        height: u64,
    ) -> Result<Vec<BulletinSurfaceEntry>, StateError> {
        let prefix = [AFT_BULLETIN_ENTRY_PREFIX, &height.to_be_bytes()].concat();
        let mut entries = Vec::new();
        for item in state.prefix_scan(&prefix)? {
            let (_, value) = item?;
            let entry: BulletinSurfaceEntry = codec::from_bytes_canonical(&value)
                .map_err(|e| StateError::InvalidValue(e.to_string()))?;
            entries.push(entry);
        }
        entries.sort_unstable_by(|left, right| left.tx_hash.cmp(&right.tx_hash));
        Ok(entries)
    }

    pub fn load_bulletin_availability_certificate(
        state: &dyn StateAccess,
        height: u64,
    ) -> Result<Option<BulletinAvailabilityCertificate>, StateError> {
        match state.get(&aft_bulletin_availability_certificate_key(height))? {
            Some(bytes) => codec::from_bytes_canonical(&bytes)
                .map(Some)
                .map_err(|e| StateError::InvalidValue(e.to_string())),
            None => Ok(None),
        }
    }

    pub fn load_canonical_bulletin_close(
        state: &dyn StateAccess,
        height: u64,
    ) -> Result<Option<CanonicalBulletinClose>, StateError> {
        match state.get(&aft_canonical_bulletin_close_key(height))? {
            Some(bytes) => codec::from_bytes_canonical(&bytes)
                .map(Some)
                .map_err(|e| StateError::InvalidValue(e.to_string())),
            None => Ok(None),
        }
    }

    pub fn extract_published_bulletin_surface(
        state: &dyn StateAccess,
        height: u64,
    ) -> Result<Option<Vec<BulletinSurfaceEntry>>, StateError> {
        let Some(bulletin_commitment) = Self::load_bulletin_commitment(state, height)? else {
            return Ok(None);
        };
        let Some(bulletin_availability_certificate) =
            Self::load_bulletin_availability_certificate(state, height)?
        else {
            return Ok(None);
        };
        let Some(bulletin_close) = Self::load_canonical_bulletin_close(state, height)? else {
            return Ok(None);
        };
        let entries = Self::load_bulletin_surface_entries(state, height)?;
        extract_canonical_bulletin_surface(
            &bulletin_close,
            &bulletin_commitment,
            &bulletin_availability_certificate,
            &entries,
        )
        .map(Some)
        .map_err(StateError::InvalidValue)
    }

    pub fn require_published_bulletin_surface(
        state: &dyn StateAccess,
        height: u64,
    ) -> Result<Vec<BulletinSurfaceEntry>, StateError> {
        let bulletin_commitment = Self::load_bulletin_commitment(state, height)?.ok_or_else(|| {
            StateError::InvalidValue(
                "published bulletin commitment is required for closed-slot extraction".into(),
            )
        })?;
        let bulletin_availability_certificate =
            Self::load_bulletin_availability_certificate(state, height)?.ok_or_else(|| {
                StateError::InvalidValue(
                    "published bulletin availability certificate is required for closed-slot extraction"
                        .into(),
                )
            })?;
        let bulletin_close =
            Self::load_canonical_bulletin_close(state, height)?.ok_or_else(|| {
                StateError::InvalidValue(
                    "canonical bulletin close is required for closed-slot extraction".into(),
                )
            })?;
        let entries = Self::load_bulletin_surface_entries(state, height)?;
        extract_canonical_bulletin_surface(
            &bulletin_close,
            &bulletin_commitment,
            &bulletin_availability_certificate,
            &entries,
        )
        .map_err(StateError::InvalidValue)
    }

    pub fn load_canonical_order_certificate(
        state: &dyn StateAccess,
        height: u64,
    ) -> Result<Option<CanonicalOrderCertificate>, StateError> {
        match state.get(&aft_order_certificate_key(height))? {
            Some(bytes) => codec::from_bytes_canonical(&bytes)
                .map(Some)
                .map_err(|e| StateError::InvalidValue(e.to_string())),
            None => Ok(None),
        }
    }

    pub fn load_canonical_order_abort(
        state: &dyn StateAccess,
        height: u64,
    ) -> Result<Option<CanonicalOrderAbort>, StateError> {
        match state.get(&aft_canonical_order_abort_key(height))? {
            Some(bytes) => codec::from_bytes_canonical(&bytes)
                .map(Some)
                .map_err(|e| StateError::InvalidValue(e.to_string())),
            None => Ok(None),
        }
    }

    pub fn load_canonical_collapse_object(
        state: &dyn StateAccess,
        height: u64,
    ) -> Result<Option<CanonicalCollapseObject>, StateError> {
        match state.get(&aft_canonical_collapse_object_key(height))? {
            Some(bytes) => codec::from_bytes_canonical(&bytes)
                .map(Some)
                .map_err(|e| StateError::InvalidValue(e.to_string())),
            None => Ok(None),
        }
    }

    pub fn load_observer_challenges(
        state: &dyn StateAccess,
        epoch: u64,
        height: u64,
        view: u64,
    ) -> Result<Vec<AsymptoteObserverChallenge>, StateError> {
        let prefix = [
            GUARDIAN_REGISTRY_OBSERVER_CHALLENGE_PREFIX,
            &epoch.to_be_bytes(),
            &height.to_be_bytes(),
            &view.to_be_bytes(),
        ]
        .concat();
        let mut challenges = Vec::new();
        for item in state.prefix_scan(&prefix)? {
            let (_, value) = item?;
            let challenge: AsymptoteObserverChallenge = codec::from_bytes_canonical(&value)
                .map_err(|e| StateError::InvalidValue(e.to_string()))?;
            challenges.push(challenge);
        }
        challenges.sort_unstable_by_key(|challenge| challenge.challenge_id);
        Ok(challenges)
    }

    pub fn load_effect_proof_verifier(
        state: &dyn StateAccess,
        verifier_id: &str,
    ) -> Result<Option<EffectProofVerifierDescriptor>, StateError> {
        match state.get(&guardian_registry_effect_verifier_key(verifier_id))? {
            Some(bytes) => codec::from_bytes_canonical(&bytes)
                .map(Some)
                .map_err(|e| StateError::InvalidValue(e.to_string())),
            None => Ok(None),
        }
    }

    fn load_quarantined_validators(
        state: &dyn StateAccess,
    ) -> Result<BTreeSet<AccountId>, TransactionError> {
        let set = state
            .get(QUARANTINED_VALIDATORS_KEY)?
            .map(|bytes| codec::from_bytes_canonical(&bytes).map_err(StateError::InvalidValue))
            .transpose()
            .map_err(TransactionError::State)?;
        Ok(set.unwrap_or_default())
    }

    fn load_evidence_registry(
        state: &dyn StateAccess,
    ) -> Result<BTreeSet<[u8; 32]>, TransactionError> {
        let set = state
            .get(EVIDENCE_REGISTRY_KEY)?
            .map(|bytes| codec::from_bytes_canonical(&bytes).map_err(StateError::InvalidValue))
            .transpose()
            .map_err(TransactionError::State)?;
        Ok(set.unwrap_or_default())
    }

    fn build_canonical_order_abort(
        height: u64,
        reason: CanonicalOrderAbortReason,
        details: impl Into<String>,
        certificate: Option<&CanonicalOrderCertificate>,
        close: Option<&CanonicalBulletinClose>,
    ) -> CanonicalOrderAbort {
        let bulletin_commitment_hash = certificate
            .and_then(|candidate| canonical_bulletin_commitment_hash(&candidate.bulletin_commitment).ok())
            .unwrap_or([0u8; 32]);
        let bulletin_availability_certificate_hash = certificate
            .and_then(|candidate| {
                canonical_bulletin_availability_certificate_hash(
                    &candidate.bulletin_availability_certificate,
                )
                .ok()
            })
            .unwrap_or([0u8; 32]);
        let bulletin_close_hash = close
            .and_then(|candidate| canonical_bulletin_close_hash(candidate).ok())
            .unwrap_or([0u8; 32]);
        let canonical_order_certificate_hash = certificate
            .and_then(|candidate| canonical_order_certificate_hash(candidate).ok())
            .unwrap_or([0u8; 32]);
        CanonicalOrderAbort {
            height,
            reason,
            details: details.into(),
            bulletin_commitment_hash,
            bulletin_availability_certificate_hash,
            bulletin_close_hash,
            canonical_order_certificate_hash,
        }
    }

    fn materialize_canonical_order_abort(
        state: &mut dyn StateAccess,
        abort: CanonicalOrderAbort,
    ) -> Result<(), TransactionError> {
        state.insert(
            &aft_canonical_order_abort_key(abort.height),
            &codec::to_bytes_canonical(&abort).map_err(TransactionError::Serialization)?,
        )?;
        state.delete(&aft_order_certificate_key(abort.height))?;
        state.delete(&aft_bulletin_availability_certificate_key(abort.height))?;
        state.delete(&aft_canonical_bulletin_close_key(abort.height))?;

        if let Some(mut collapse) =
            Self::load_canonical_collapse_object(state, abort.height).map_err(TransactionError::State)?
        {
            collapse.ordering.kind = CanonicalCollapseKind::Abort;
            if abort.bulletin_commitment_hash != [0u8; 32] {
                collapse.ordering.bulletin_commitment_hash = abort.bulletin_commitment_hash;
            }
            if abort.bulletin_availability_certificate_hash != [0u8; 32] {
                collapse.ordering.bulletin_availability_certificate_hash =
                    abort.bulletin_availability_certificate_hash;
            }
            if abort.bulletin_close_hash != [0u8; 32] {
                collapse.ordering.bulletin_close_hash = abort.bulletin_close_hash;
            }
            if abort.canonical_order_certificate_hash != [0u8; 32] {
                collapse.ordering.canonical_order_certificate_hash =
                    abort.canonical_order_certificate_hash;
            }
            let previous = if collapse.height <= 1 {
                None
            } else {
                Self::load_canonical_collapse_object(state, collapse.height - 1)
                    .map_err(TransactionError::State)?
            };
            bind_canonical_collapse_continuity(&mut collapse, previous.as_ref())
                .map_err(TransactionError::Invalid)?;
            state.insert(
                &aft_canonical_collapse_object_key(collapse.height),
                &codec::to_bytes_canonical(&collapse).map_err(TransactionError::Serialization)?,
            )?;
        }
        Ok(())
    }

    fn materialize_observer_abort(
        state: &mut dyn StateAccess,
        abort: AsymptoteObserverCanonicalAbort,
    ) -> Result<(), TransactionError> {
        state.delete(&guardian_registry_observer_canonical_close_key(
            abort.epoch,
            abort.height,
            abort.view,
        ))?;
        state.insert(
            &guardian_registry_observer_canonical_abort_key(abort.epoch, abort.height, abort.view),
            &codec::to_bytes_canonical(&abort).map_err(TransactionError::Serialization)?,
        )?;

        if let Some(mut collapse) =
            Self::load_canonical_collapse_object(state, abort.height).map_err(TransactionError::State)?
        {
            if let Some(sealing) = collapse.sealing.as_mut() {
                if sealing.epoch == abort.epoch && sealing.height == abort.height && sealing.view == abort.view
                {
                    sealing.kind = CanonicalCollapseKind::Abort;
                    sealing.finality_tier = FinalityTier::BaseFinal;
                    sealing.collapse_state = CollapseState::Abort;
                    sealing.transcripts_root = abort.transcripts_root;
                    sealing.challenges_root = abort.challenges_root;
                    sealing.resolution_hash =
                        canonical_asymptote_observer_canonical_abort_hash(&abort)
                            .map_err(TransactionError::Invalid)?;
                    let previous = if collapse.height <= 1 {
                        None
                    } else {
                        Self::load_canonical_collapse_object(state, collapse.height - 1)
                            .map_err(TransactionError::State)?
                    };
                    bind_canonical_collapse_continuity(&mut collapse, previous.as_ref())
                        .map_err(TransactionError::Invalid)?;
                    state.insert(
                        &aft_canonical_collapse_object_key(collapse.height),
                        &codec::to_bytes_canonical(&collapse)
                            .map_err(TransactionError::Serialization)?,
                    )?;
                }
            }
        }
        Ok(())
    }

    fn refresh_observer_challenge_surface(
        state: &mut dyn StateAccess,
        challenge: &AsymptoteObserverChallenge,
    ) -> Result<(), TransactionError> {
        let challenges = Self::load_observer_challenges(
            state,
            challenge.epoch,
            challenge.height,
            challenge.view,
        )
        .map_err(TransactionError::State)?;
        let challenges_root =
            canonical_asymptote_observer_challenges_hash(&challenges).map_err(TransactionError::Invalid)?;
        let challenge_count = u16::try_from(challenges.len())
            .map_err(|_| TransactionError::Invalid("observer challenge count exceeds u16".into()))?;
        let challenge_commitment = AsymptoteObserverChallengeCommitment {
            epoch: challenge.epoch,
            height: challenge.height,
            view: challenge.view,
            challenges_root,
            challenge_count,
        };
        state.insert(
            &guardian_registry_observer_challenge_commitment_key(
                challenge.epoch,
                challenge.height,
                challenge.view,
            ),
            &codec::to_bytes_canonical(&challenge_commitment)
                .map_err(TransactionError::Serialization)?,
        )?;

        let abort_basis = challenge
            .canonical_close
            .clone()
            .map(|close| {
                (
                    close.assignments_hash,
                    close.transcripts_root,
                    close.transcript_count,
                    close.challenge_cutoff_timestamp_ms,
                )
            })
            .or_else(|| {
                Self::load_asymptote_observer_canonical_close(
                    state,
                    challenge.epoch,
                    challenge.height,
                    challenge.view,
                )
                .ok()
                .flatten()
                .map(|close| {
                    (
                        close.assignments_hash,
                        close.transcripts_root,
                        close.transcript_count,
                        close.challenge_cutoff_timestamp_ms,
                    )
                })
            })
            .or_else(|| {
                Self::load_asymptote_observer_canonical_abort(
                    state,
                    challenge.epoch,
                    challenge.height,
                    challenge.view,
                )
                .ok()
                .flatten()
                .map(|abort| {
                    (
                        abort.assignments_hash,
                        abort.transcripts_root,
                        abort.transcript_count,
                        abort.challenge_cutoff_timestamp_ms,
                    )
                })
            });

        if let Some((assignments_hash, transcripts_root, transcript_count, challenge_cutoff_timestamp_ms)) =
            abort_basis
        {
            Self::materialize_observer_abort(
                state,
                AsymptoteObserverCanonicalAbort {
                    epoch: challenge.epoch,
                    height: challenge.height,
                    view: challenge.view,
                    assignments_hash,
                    transcripts_root,
                    challenges_root,
                    transcript_count,
                    challenge_count,
                    challenge_cutoff_timestamp_ms,
                },
            )?;
        }

        Ok(())
    }

    fn observation_request_producer_account(
        challenge: &AsymptoteObserverChallenge,
    ) -> Option<AccountId> {
        challenge
            .assignment
            .as_ref()
            .map(|assignment| assignment.producer_account_id)
            .or_else(|| {
                challenge
                    .observation_request
                    .as_ref()
                    .map(|request| request.assignment.producer_account_id)
            })
            .or_else(|| {
                challenge
                    .transcript
                    .as_ref()
                    .map(|transcript| transcript.statement.assignment.producer_account_id)
            })
    }

    fn observation_request_observer_account(
        challenge: &AsymptoteObserverChallenge,
    ) -> Option<AccountId> {
        challenge
            .assignment
            .as_ref()
            .map(|assignment| assignment.observer_account_id)
            .or_else(|| {
                challenge
                    .observation_request
                    .as_ref()
                    .map(|request| request.assignment.observer_account_id)
            })
            .or_else(|| {
                challenge
                    .transcript
                    .as_ref()
                    .map(|transcript| transcript.statement.assignment.observer_account_id)
            })
    }

    fn accountable_challenge_offender(
        challenge: &AsymptoteObserverChallenge,
    ) -> Option<AccountId> {
        match challenge.kind {
            AsymptoteObserverChallengeKind::MissingTranscript
            | AsymptoteObserverChallengeKind::ConflictingTranscript => {
                Self::observation_request_observer_account(challenge)
            }
            AsymptoteObserverChallengeKind::TranscriptMismatch
            | AsymptoteObserverChallengeKind::VetoTranscriptPresent => {
                Self::observation_request_producer_account(challenge)
            }
            AsymptoteObserverChallengeKind::InvalidCanonicalClose => Self::observation_request_producer_account(challenge)
                .or_else(|| Some(challenge.challenger_account_id)),
        }
    }

    fn omission_failure_report(omission: &OmissionProof) -> Result<FailureReport, TransactionError> {
        let proof = codec::to_bytes_canonical(omission).map_err(TransactionError::Serialization)?;
        Ok(FailureReport {
            offender: omission.offender_account_id,
            offense_type: OffenseType::AftOrderingOmission,
            facts: OffenseFacts::AftOrderingOmission {
                height: omission.height,
                tx_hash: omission.tx_hash,
                bulletin_root: omission.bulletin_root,
            },
            proof,
        })
    }

    fn observer_challenge_failure_report(
        challenge: &AsymptoteObserverChallenge,
    ) -> Result<Option<FailureReport>, TransactionError> {
        let Some(offender) = Self::accountable_challenge_offender(challenge) else {
            return Ok(None);
        };
        let proof = codec::to_bytes_canonical(challenge).map_err(TransactionError::Serialization)?;
        Ok(Some(FailureReport {
            offender,
            offense_type: OffenseType::AftObserverChallenge,
            facts: OffenseFacts::AftObserverChallenge {
                challenge_id: challenge.challenge_id,
                epoch: challenge.epoch,
                height: challenge.height,
                view: challenge.view,
                kind: challenge.kind,
                evidence_hash: challenge.evidence_hash,
            },
            proof,
        }))
    }

    fn validate_observer_challenge_shape(
        challenge: &AsymptoteObserverChallenge,
    ) -> Result<(), TransactionError> {
        match challenge.kind {
            AsymptoteObserverChallengeKind::MissingTranscript => {
                let assignment = challenge.assignment.as_ref().ok_or_else(|| {
                    TransactionError::Invalid(
                        "missing-transcript challenge must carry an assignment".into(),
                    )
                })?;
                if challenge.observation_request.is_some()
                    || challenge.transcript.is_some()
                    || challenge.canonical_close.is_some()
                {
                    return Err(TransactionError::Invalid(
                        "missing-transcript challenge may only carry assignment evidence".into(),
                    ));
                }
                let expected_hash = canonical_asymptote_observer_assignment_hash(assignment)
                    .map_err(TransactionError::Invalid)?;
                if challenge.evidence_hash != expected_hash {
                    return Err(TransactionError::Invalid(
                        "missing-transcript challenge evidence hash does not match the assignment"
                            .into(),
                    ));
                }
            }
            AsymptoteObserverChallengeKind::TranscriptMismatch => {
                let request = challenge.observation_request.as_ref().ok_or_else(|| {
                    TransactionError::Invalid(
                        "transcript-mismatch challenge must carry an observation request".into(),
                    )
                })?;
                if challenge.assignment.is_none()
                    || challenge.transcript.is_some()
                    || challenge.canonical_close.is_some()
                {
                    return Err(TransactionError::Invalid(
                        "transcript-mismatch challenge must carry only assignment and observation-request evidence".into(),
                    ));
                }
                let expected_hash = canonical_asymptote_observer_observation_request_hash(request)
                    .map_err(TransactionError::Invalid)?;
                if challenge.evidence_hash != expected_hash {
                    return Err(TransactionError::Invalid(
                        "transcript-mismatch challenge evidence hash does not match the offending request".into(),
                    ));
                }
            }
            AsymptoteObserverChallengeKind::VetoTranscriptPresent
            | AsymptoteObserverChallengeKind::ConflictingTranscript => {
                let transcript = challenge.transcript.as_ref().ok_or_else(|| {
                    TransactionError::Invalid(
                        "transcript-based observer challenge must carry a transcript".into(),
                    )
                })?;
                if challenge.assignment.is_none()
                    || challenge.observation_request.is_some()
                    || challenge.canonical_close.is_some()
                {
                    return Err(TransactionError::Invalid(
                        "transcript-based observer challenge must carry only assignment and transcript evidence".into(),
                    ));
                }
                let expected_hash = canonical_asymptote_observer_transcript_hash(transcript)
                    .map_err(TransactionError::Invalid)?;
                if challenge.evidence_hash != expected_hash {
                    return Err(TransactionError::Invalid(
                        "observer challenge evidence hash does not match the offending transcript"
                            .into(),
                    ));
                }
            }
            AsymptoteObserverChallengeKind::InvalidCanonicalClose => {
                let close = challenge.canonical_close.as_ref().ok_or_else(|| {
                    TransactionError::Invalid(
                        "invalid-canonical-close challenge must carry the offending canonical close"
                            .into(),
                    )
                })?;
                if challenge.assignment.is_some()
                    || challenge.observation_request.is_some()
                    || challenge.transcript.is_some()
                {
                    return Err(TransactionError::Invalid(
                        "invalid-canonical-close challenge may only carry canonical-close evidence"
                            .into(),
                    ));
                }
                let expected_hash = canonical_asymptote_observer_canonical_close_hash(close)
                    .map_err(TransactionError::Invalid)?;
                if challenge.evidence_hash != expected_hash {
                    return Err(TransactionError::Invalid(
                        "invalid-canonical-close challenge evidence hash does not match the offending close".into(),
                    ));
                }
            }
        }
        Ok(())
    }

    fn apply_accountable_membership_updates(
        state: &mut dyn StateAccess,
        offender: AccountId,
        block_height: u64,
    ) -> Result<(), TransactionError> {
        let Some(validator_set_bytes) = state.get(VALIDATOR_SET_KEY)? else {
            return Ok(());
        };
        let mut sets = read_validator_sets(&validator_set_bytes).map_err(TransactionError::State)?;
        let active_set = effective_set_for_height(&sets, block_height).clone();

        let active_accounts = active_set
            .validators
            .iter()
            .map(|validator| validator.account_id)
            .collect::<Vec<_>>();

        let mut quarantined = Self::load_quarantined_validators(state)?;
        if active_accounts.contains(&offender) && !quarantined.contains(&offender) {
            let live_after = active_accounts
                .len()
                .saturating_sub(quarantined.len())
                .saturating_sub(1);
            if live_after >= 2 {
                quarantined.insert(offender);
                state.insert(
                    QUARANTINED_VALIDATORS_KEY,
                    &codec::to_bytes_canonical(&quarantined)
                        .map_err(TransactionError::Serialization)?,
                )?;
            }
        }

        let mut staged_next = match sets.next.clone() {
            Some(next) if next.effective_from_height > block_height => next,
            _ => {
                let mut next = active_set.clone();
                next.effective_from_height = block_height.saturating_add(1);
                next
            }
        };
        if staged_next.validators.len() <= 1 {
            return Ok(());
        }

        let original_len = staged_next.validators.len();
        staged_next
            .validators
            .retain(|validator| validator.account_id != offender);
        if staged_next.validators.len() == original_len {
            return Ok(());
        }

        staged_next.total_weight = staged_next.validators.iter().map(|validator| validator.weight).sum();
        sets.next = Some(staged_next);
        state.insert(
            VALIDATOR_SET_KEY,
            &write_validator_sets(&sets).map_err(TransactionError::State)?,
        )?;
        Ok(())
    }

    fn apply_accountable_fault_report(
        state: &mut dyn StateAccess,
        report: FailureReport,
        block_height: u64,
        apply_membership_updates: bool,
    ) -> Result<(), TransactionError> {
        let evidence_key =
            evidence_id(&report).map_err(|error| TransactionError::Invalid(error.to_string()))?;
        let mut evidence_registry = Self::load_evidence_registry(state)?;
        if !evidence_registry.insert(evidence_key) {
            return Ok(());
        }

        state.insert(
            EVIDENCE_REGISTRY_KEY,
            &codec::to_bytes_canonical(&evidence_registry)
                .map_err(TransactionError::Serialization)?,
        )?;
        if !apply_membership_updates {
            return Ok(());
        }
        if let Err(error) =
            Self::apply_accountable_membership_updates(state, report.offender, block_height)
        {
            warn!(
                offender = ?report.offender,
                block_height,
                error = %error,
                "accountable membership updates failed after evidence publication; leaving negative object decisive"
            );
        }
        Ok(())
    }

    pub fn load_asymptote_observer_transcript_commitment(
        state: &dyn StateAccess,
        epoch: u64,
        height: u64,
        view: u64,
    ) -> Result<Option<AsymptoteObserverTranscriptCommitment>, StateError> {
        match state.get(&guardian_registry_observer_transcript_commitment_key(epoch, height, view))?
        {
            Some(bytes) => codec::from_bytes_canonical(&bytes)
                .map(Some)
                .map_err(|e| StateError::InvalidValue(e.to_string())),
            None => Ok(None),
        }
    }

    pub fn load_asymptote_observer_challenge_commitment(
        state: &dyn StateAccess,
        epoch: u64,
        height: u64,
        view: u64,
    ) -> Result<Option<AsymptoteObserverChallengeCommitment>, StateError> {
        match state.get(&guardian_registry_observer_challenge_commitment_key(
            epoch, height, view,
        ))? {
            Some(bytes) => codec::from_bytes_canonical(&bytes)
                .map(Some)
                .map_err(|e| StateError::InvalidValue(e.to_string())),
            None => Ok(None),
        }
    }

    pub fn load_asymptote_observer_canonical_close(
        state: &dyn StateAccess,
        epoch: u64,
        height: u64,
        view: u64,
    ) -> Result<Option<AsymptoteObserverCanonicalClose>, StateError> {
        match state.get(&guardian_registry_observer_canonical_close_key(epoch, height, view))? {
            Some(bytes) => codec::from_bytes_canonical(&bytes)
                .map(Some)
                .map_err(|e| StateError::InvalidValue(e.to_string())),
            None => Ok(None),
        }
    }

    pub fn load_asymptote_observer_canonical_abort(
        state: &dyn StateAccess,
        epoch: u64,
        height: u64,
        view: u64,
    ) -> Result<Option<AsymptoteObserverCanonicalAbort>, StateError> {
        match state.get(&guardian_registry_observer_canonical_abort_key(epoch, height, view))? {
            Some(bytes) => codec::from_bytes_canonical(&bytes)
                .map(Some)
                .map_err(|e| StateError::InvalidValue(e.to_string())),
            None => Ok(None),
        }
    }

    pub fn load_sealed_effect_record(
        state: &dyn StateAccess,
        intent_hash: &[u8; 32],
    ) -> Result<Option<SealedEffectRecord>, StateError> {
        match state.get(&guardian_registry_sealed_effect_key(intent_hash))? {
            Some(bytes) => codec::from_bytes_canonical(&bytes)
                .map(Some)
                .map_err(|e| StateError::InvalidValue(e.to_string())),
            None => Ok(None),
        }
    }

    fn validate_diversity(
        labels: impl Iterator<Item = Option<String>>,
        minimum: u16,
        field: &str,
    ) -> Result<(), TransactionError> {
        if minimum == 0 {
            return Ok(());
        }

        let distinct = labels
            .flatten()
            .filter(|value| !value.trim().is_empty())
            .collect::<BTreeSet<_>>();

        if distinct.len() < usize::from(minimum) {
            return Err(TransactionError::Invalid(format!(
                "guardian registry policy requires at least {} distinct {} labels, got {}",
                minimum,
                field,
                distinct.len()
            )));
        }
        Ok(())
    }

    fn validate_committee_manifest(
        &self,
        manifest: &GuardianCommitteeManifest,
    ) -> Result<(), TransactionError> {
        let member_count = manifest.members.len();
        if member_count < usize::from(self.config.minimum_committee_size) {
            return Err(TransactionError::Invalid(format!(
                "guardian committee size {} is below minimum {}",
                member_count, self.config.minimum_committee_size
            )));
        }
        if member_count == 0 {
            return Err(TransactionError::Invalid(
                "guardian committee must contain at least one member".into(),
            ));
        }
        if manifest.threshold == 0 || usize::from(manifest.threshold) > member_count {
            return Err(TransactionError::Invalid(format!(
                "guardian committee threshold {} is invalid for size {}",
                manifest.threshold, member_count
            )));
        }
        if usize::from(manifest.threshold) <= member_count / 2 {
            return Err(TransactionError::Invalid(
                "guardian committee threshold must be a strict majority".into(),
            ));
        }
        if self.config.require_even_committee_sizes && member_count % 2 != 0 {
            return Err(TransactionError::Invalid(
                "production guardian committees must be even-sized in registry policy".into(),
            ));
        }
        if self.config.require_checkpoint_anchoring
            && manifest.transparency_log_id.trim().is_empty()
        {
            return Err(TransactionError::Invalid(
                "guardian committee must declare a transparency log id".into(),
            ));
        }

        Self::validate_diversity(
            manifest
                .members
                .iter()
                .map(|member| member.provider.clone()),
            self.config.minimum_provider_diversity,
            "provider",
        )?;
        Self::validate_diversity(
            manifest.members.iter().map(|member| member.region.clone()),
            self.config.minimum_region_diversity,
            "region",
        )?;
        Self::validate_diversity(
            manifest
                .members
                .iter()
                .map(|member| member.host_class.clone()),
            self.config.minimum_host_class_diversity,
            "host class",
        )?;
        Self::validate_diversity(
            manifest
                .members
                .iter()
                .map(|member| member.key_authority_kind.map(|kind| format!("{kind:?}"))),
            self.config.minimum_backend_diversity,
            "key authority",
        )?;

        Ok(())
    }

    fn validate_witness_manifest(
        &self,
        manifest: &GuardianWitnessCommitteeManifest,
    ) -> Result<(), TransactionError> {
        let member_count = manifest.members.len();
        if member_count < usize::from(self.config.minimum_witness_committee_size) {
            return Err(TransactionError::Invalid(format!(
                "witness committee size {} is below minimum {}",
                member_count, self.config.minimum_witness_committee_size
            )));
        }
        if manifest.threshold == 0 || usize::from(manifest.threshold) > member_count {
            return Err(TransactionError::Invalid(format!(
                "witness committee threshold {} is invalid for size {}",
                manifest.threshold, member_count
            )));
        }
        if usize::from(manifest.threshold) <= member_count / 2 {
            return Err(TransactionError::Invalid(
                "witness committee threshold must be a strict majority".into(),
            ));
        }
        if self.config.require_even_committee_sizes && member_count % 2 != 0 {
            return Err(TransactionError::Invalid(
                "production witness committees must be even-sized in registry policy".into(),
            ));
        }
        if self.config.require_checkpoint_anchoring
            && manifest.transparency_log_id.trim().is_empty()
        {
            return Err(TransactionError::Invalid(
                "witness committee must declare a transparency log id".into(),
            ));
        }
        if manifest.stratum_id.trim().is_empty() {
            return Err(TransactionError::Invalid(
                "witness committee must declare a certification stratum".into(),
            ));
        }

        Self::validate_diversity(
            manifest
                .members
                .iter()
                .map(|member| member.provider.clone()),
            self.config.minimum_provider_diversity,
            "provider",
        )?;
        Self::validate_diversity(
            manifest.members.iter().map(|member| member.region.clone()),
            self.config.minimum_region_diversity,
            "region",
        )?;
        Self::validate_diversity(
            manifest
                .members
                .iter()
                .map(|member| member.host_class.clone()),
            self.config.minimum_host_class_diversity,
            "host class",
        )?;
        Self::validate_diversity(
            manifest
                .members
                .iter()
                .map(|member| member.key_authority_kind.map(|kind| format!("{kind:?}"))),
            self.config.minimum_backend_diversity,
            "key authority",
        )?;

        Ok(())
    }

    fn validate_log_descriptor(
        &self,
        descriptor: &GuardianTransparencyLogDescriptor,
    ) -> Result<(), TransactionError> {
        if descriptor.log_id.trim().is_empty() {
            return Err(TransactionError::Invalid(
                "guardian transparency log id must not be empty".into(),
            ));
        }
        if descriptor.public_key.is_empty() {
            return Err(TransactionError::Invalid(
                "guardian transparency log public key must not be empty".into(),
            ));
        }
        Ok(())
    }
}

#[async_trait]
impl BlockchainService for GuardianRegistry {
    fn id(&self) -> &str {
        "guardian_registry"
    }

    fn abi_version(&self) -> u32 {
        1
    }

    fn state_schema(&self) -> &str {
        "guardian_registry/v1"
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities::empty()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    async fn handle_service_call(
        &self,
        state: &mut dyn StateAccess,
        method: &str,
        params: &[u8],
        ctx: &mut TxContext<'_>,
    ) -> Result<(), TransactionError> {
        match method {
            "register_guardian_transparency_log@v1" => {
                let descriptor: GuardianTransparencyLogDescriptor =
                    codec::from_bytes_canonical(params)?;
                self.validate_log_descriptor(&descriptor)?;
                state.insert(
                    &guardian_registry_log_key(&descriptor.log_id),
                    &codec::to_bytes_canonical(&descriptor)
                        .map_err(TransactionError::Serialization)?,
                )?;
                Ok(())
            }
            "register_guardian_committee@v1" => {
                let manifest: GuardianCommitteeManifest = codec::from_bytes_canonical(params)?;
                self.validate_committee_manifest(&manifest)?;
                let manifest_hash = Self::manifest_hash(&manifest)?;
                state.insert(
                    &guardian_registry_committee_key(&manifest_hash),
                    &codec::to_bytes_canonical(&manifest)
                        .map_err(TransactionError::Serialization)?,
                )?;
                state.insert(
                    &guardian_registry_committee_account_key(&manifest.validator_account_id),
                    manifest_hash.as_ref(),
                )?;
                Ok(())
            }
            "publish_measurement_profile@v1" => {
                let profile: GuardianMeasurementProfile = codec::from_bytes_canonical(params)?;
                state.insert(
                    &[
                        GUARDIAN_REGISTRY_MEASUREMENT_PREFIX,
                        profile.profile_id.as_bytes(),
                    ]
                    .concat(),
                    &codec::to_bytes_canonical(&profile)
                        .map_err(TransactionError::Serialization)?,
                )?;
                if profile.profile_id == "default" {
                    state.insert(
                        &[GUARDIAN_REGISTRY_MEASUREMENT_PREFIX, b"default"].concat(),
                        &codec::to_bytes_canonical(&profile)
                            .map_err(TransactionError::Serialization)?,
                    )?;
                }
                Ok(())
            }
            "register_guardian_witness_committee@v1" => {
                let manifest: GuardianWitnessCommitteeManifest =
                    codec::from_bytes_canonical(params)?;
                self.validate_witness_manifest(&manifest)?;
                let manifest_hash = sha256(
                    &codec::to_bytes_canonical(&manifest)
                        .map_err(TransactionError::Serialization)?,
                )
                .map_err(|e| TransactionError::Invalid(e.to_string()))
                .and_then(|digest| {
                    digest.try_into().map_err(|_| {
                        TransactionError::Invalid("invalid witness manifest hash length".into())
                    })
                })?;
                state.insert(
                    &guardian_registry_witness_key(&manifest_hash),
                    &codec::to_bytes_canonical(&manifest)
                        .map_err(TransactionError::Serialization)?,
                )?;
                let active_key = guardian_registry_witness_set_key(manifest.epoch);
                let mut active_set = match state.get(&active_key)? {
                    Some(bytes) => codec::from_bytes_canonical::<GuardianWitnessSet>(&bytes)?,
                    None => GuardianWitnessSet {
                        epoch: manifest.epoch,
                        manifest_hashes: Vec::new(),
                        checkpoint_interval_blocks: 1,
                    },
                };
                if !active_set.manifest_hashes.contains(&manifest_hash) {
                    active_set.manifest_hashes.push(manifest_hash);
                    active_set.manifest_hashes.sort_unstable();
                }
                state.insert(
                    &active_key,
                    &codec::to_bytes_canonical(&active_set)
                        .map_err(TransactionError::Serialization)?,
                )?;
                Ok(())
            }
            "publish_witness_epoch_seed@v1" => {
                let seed: GuardianWitnessEpochSeed = codec::from_bytes_canonical(params)?;
                state.insert(
                    &guardian_registry_witness_seed_key(seed.epoch),
                    &codec::to_bytes_canonical(&seed).map_err(TransactionError::Serialization)?,
                )?;
                let active_key = guardian_registry_witness_set_key(seed.epoch);
                let mut active_set = match state.get(&active_key)? {
                    Some(bytes) => codec::from_bytes_canonical::<GuardianWitnessSet>(&bytes)?,
                    None => GuardianWitnessSet {
                        epoch: seed.epoch,
                        manifest_hashes: Vec::new(),
                        checkpoint_interval_blocks: seed.checkpoint_interval_blocks,
                    },
                };
                active_set.checkpoint_interval_blocks = seed.checkpoint_interval_blocks;
                state.insert(
                    &active_key,
                    &codec::to_bytes_canonical(&active_set)
                        .map_err(TransactionError::Serialization)?,
                )?;
                Ok(())
            }
            "publish_asymptote_policy@v1" => {
                let policy: AsymptotePolicy = codec::from_bytes_canonical(params)?;
                let witness_mode = !policy.required_witness_strata.is_empty()
                    || !policy.escalation_witness_strata.is_empty();
                let observer_mode =
                    policy.observer_rounds > 0 || policy.observer_committee_size > 0;
                if !witness_mode && !observer_mode {
                    return Err(TransactionError::Invalid(
                        "asymptote policy requires either witness strata or equal-authority observer sampling".into(),
                    ));
                }
                if observer_mode
                    && (policy.observer_rounds == 0 || policy.observer_committee_size == 0)
                {
                    return Err(TransactionError::Invalid(
                        "asymptote equal-authority observer mode requires non-zero rounds and committee size".into(),
                    ));
                }
                if matches!(
                    policy.observer_sealing_mode,
                    AsymptoteObserverSealingMode::CanonicalChallengeV1
                ) && !observer_mode
                {
                    return Err(TransactionError::Invalid(
                        "canonical observer sealing mode requires equal-authority observer assignments"
                            .into(),
                    ));
                }
                if matches!(
                    policy.observer_sealing_mode,
                    AsymptoteObserverSealingMode::CanonicalChallengeV1
                ) && policy.observer_challenge_window_ms == 0
                {
                    return Err(TransactionError::Invalid(
                        "canonical observer sealing mode requires a non-zero challenge window"
                            .into(),
                    ));
                }
                if witness_mode {
                    if policy.required_witness_strata.is_empty() {
                        return Err(TransactionError::Invalid(
                            "asymptote witness mode requires at least one base witness stratum"
                                .into(),
                        ));
                    }
                    let required = policy
                        .required_witness_strata
                        .iter()
                        .map(|stratum| stratum.trim())
                        .collect::<std::collections::BTreeSet<_>>();
                    let escalation = policy
                        .escalation_witness_strata
                        .iter()
                        .map(|stratum| stratum.trim())
                        .collect::<std::collections::BTreeSet<_>>();
                    if required.contains("") || escalation.contains("") {
                        return Err(TransactionError::Invalid(
                            "asymptote witness strata must not be empty".into(),
                        ));
                    }
                    if required.len() != policy.required_witness_strata.len()
                        || escalation.len() != policy.escalation_witness_strata.len()
                    {
                        return Err(TransactionError::Invalid(
                            "asymptote witness strata must be unique".into(),
                        ));
                    }
                    if !required.is_subset(&escalation) {
                        return Err(TransactionError::Invalid(
                            "asymptote escalation strata must include all base strata".into(),
                        ));
                    }
                }
                if policy.max_checkpoint_staleness_ms > 0
                    && policy.max_checkpoint_staleness_ms < self.config.max_checkpoint_staleness_ms
                {
                    return Err(TransactionError::Invalid(
                        "asymptote checkpoint staleness cannot be weaker than guardian registry policy"
                            .into(),
                    ));
                }
                state.insert(
                    &guardian_registry_asymptote_policy_key(policy.epoch),
                    &codec::to_bytes_canonical(&policy).map_err(TransactionError::Serialization)?,
                )?;
                Ok(())
            }
            "publish_asymptote_observer_transcript_commitment@v1" => {
                let commitment: AsymptoteObserverTranscriptCommitment =
                    codec::from_bytes_canonical(params)?;
                if commitment.epoch == 0 || commitment.height == 0 {
                    return Err(TransactionError::Invalid(
                        "observer transcript commitment requires non-zero epoch and height".into(),
                    ));
                }
                state.insert(
                    &guardian_registry_observer_transcript_commitment_key(
                        commitment.epoch,
                        commitment.height,
                        commitment.view,
                    ),
                    &codec::to_bytes_canonical(&commitment)
                        .map_err(TransactionError::Serialization)?,
                )?;
                Ok(())
            }
            "publish_asymptote_observer_transcript@v1" => {
                let transcript: AsymptoteObserverTranscript = codec::from_bytes_canonical(params)?;
                if transcript.statement.epoch == 0 || transcript.statement.assignment.height == 0 {
                    return Err(TransactionError::Invalid(
                        "observer transcript requires non-zero epoch and height".into(),
                    ));
                }
                state.insert(
                    &guardian_registry_observer_transcript_key(
                        transcript.statement.epoch,
                        transcript.statement.assignment.height,
                        transcript.statement.assignment.view,
                        transcript.statement.assignment.round,
                        &transcript.statement.assignment.observer_account_id,
                    ),
                    &codec::to_bytes_canonical(&transcript)
                        .map_err(TransactionError::Serialization)?,
                )?;
                Ok(())
            }
            "publish_asymptote_observer_challenge_commitment@v1" => {
                let commitment: AsymptoteObserverChallengeCommitment =
                    codec::from_bytes_canonical(params)?;
                if commitment.epoch == 0 || commitment.height == 0 {
                    return Err(TransactionError::Invalid(
                        "observer challenge commitment requires non-zero epoch and height".into(),
                    ));
                }
                state.insert(
                    &guardian_registry_observer_challenge_commitment_key(
                        commitment.epoch,
                        commitment.height,
                        commitment.view,
                    ),
                    &codec::to_bytes_canonical(&commitment)
                        .map_err(TransactionError::Serialization)?,
                )?;
                Ok(())
            }
            "report_asymptote_observer_challenge@v1" => {
                let challenge: AsymptoteObserverChallenge = codec::from_bytes_canonical(params)?;
                if challenge.epoch == 0
                    || challenge.height == 0
                    || challenge.challenge_id == [0u8; 32]
                {
                    return Err(TransactionError::Invalid(
                        "observer challenge requires non-zero epoch, height, and challenge id"
                            .into(),
                    ));
                }
                Self::validate_observer_challenge_shape(&challenge)?;
                state.insert(
                    &guardian_registry_observer_challenge_key(
                        challenge.epoch,
                        challenge.height,
                        challenge.view,
                        &challenge.challenge_id,
                    ),
                    &codec::to_bytes_canonical(&challenge)
                        .map_err(TransactionError::Serialization)?,
                )?;
                Self::refresh_observer_challenge_surface(state, &challenge)?;
                if let Some(report) = Self::observer_challenge_failure_report(&challenge)? {
                    Self::apply_accountable_fault_report(
                        state,
                        report,
                        ctx.block_height,
                        self.config.apply_accountable_membership_updates,
                    )?;
                }
                Ok(())
            }
            "publish_asymptote_observer_canonical_close@v1" => {
                let close: AsymptoteObserverCanonicalClose = codec::from_bytes_canonical(params)?;
                if close.epoch == 0 || close.height == 0 {
                    return Err(TransactionError::Invalid(
                        "observer canonical close requires non-zero epoch and height".into(),
                    ));
                }
                if let Some(existing_abort) = Self::load_asymptote_observer_canonical_abort(
                    state,
                    close.epoch,
                    close.height,
                    close.view,
                )? {
                    return Err(TransactionError::Invalid(format!(
                        "cannot publish observer canonical close after canonical abort is already persisted for {}/{}/{}",
                        existing_abort.epoch, existing_abort.height, existing_abort.view
                    )));
                }
                if let Some(existing_commitment) = Self::load_asymptote_observer_challenge_commitment(
                    state,
                    close.epoch,
                    close.height,
                    close.view,
                )? {
                    if existing_commitment.challenge_count > 0 {
                        return Err(TransactionError::Invalid(
                            "cannot publish observer canonical close once the stored challenge surface is non-empty"
                                .into(),
                        ));
                    }
                }
                if let Some(existing_close) = Self::load_asymptote_observer_canonical_close(
                    state,
                    close.epoch,
                    close.height,
                    close.view,
                )? {
                    if existing_close != close {
                        return Err(TransactionError::Invalid(
                            "conflicting observer canonical close already published for slot"
                                .into(),
                        ));
                    }
                    return Ok(());
                }
                state.insert(
                    &guardian_registry_observer_canonical_close_key(
                        close.epoch,
                        close.height,
                        close.view,
                    ),
                    &codec::to_bytes_canonical(&close)
                        .map_err(TransactionError::Serialization)?,
                )?;
                Ok(())
            }
            "publish_asymptote_observer_canonical_abort@v1" => {
                let abort: AsymptoteObserverCanonicalAbort = codec::from_bytes_canonical(params)?;
                if abort.epoch == 0 || abort.height == 0 {
                    return Err(TransactionError::Invalid(
                        "observer canonical abort requires non-zero epoch and height".into(),
                    ));
                }
                if let Some(existing_abort) = Self::load_asymptote_observer_canonical_abort(
                    state,
                    abort.epoch,
                    abort.height,
                    abort.view,
                )? {
                    if existing_abort != abort {
                        return Err(TransactionError::Invalid(
                            "conflicting observer canonical abort already published for slot"
                                .into(),
                        ));
                    }
                    return Ok(());
                }
                Self::materialize_observer_abort(state, abort)?;
                Ok(())
            }
            "register_effect_proof_verifier@v1" => {
                let verifier: EffectProofVerifierDescriptor = codec::from_bytes_canonical(params)?;
                if verifier.verifier_id.trim().is_empty() {
                    return Err(TransactionError::Invalid(
                        "effect proof verifier id must not be empty".into(),
                    ));
                }
                state.insert(
                    &guardian_registry_effect_verifier_key(&verifier.verifier_id),
                    &codec::to_bytes_canonical(&verifier)
                        .map_err(TransactionError::Serialization)?,
                )?;
                Ok(())
            }
            "record_sealed_effect@v1" => {
                let record: SealedEffectRecord = codec::from_bytes_canonical(params)?;
                if record.nullifier == [0u8; 32] {
                    return Err(TransactionError::Invalid(
                        "sealed effect nullifier must be non-zero".into(),
                    ));
                }
                if record.intent_hash == [0u8; 32] {
                    return Err(TransactionError::Invalid(
                        "sealed effect intent hash must be non-zero".into(),
                    ));
                }
                if record.verifier_id.trim().is_empty() {
                    return Err(TransactionError::Invalid(
                        "sealed effect verifier id must not be empty".into(),
                    ));
                }
                let bytes =
                    codec::to_bytes_canonical(&record).map_err(TransactionError::Serialization)?;
                state.insert(
                    &guardian_registry_effect_nullifier_key(&record.nullifier),
                    &bytes,
                )?;
                state.insert(
                    &guardian_registry_sealed_effect_key(&record.intent_hash),
                    &bytes,
                )?;
                Ok(())
            }
            "publish_aft_bulletin_commitment@v1" => {
                let bulletin: BulletinCommitment = codec::from_bytes_canonical(params)?;
                if bulletin.height == 0 {
                    return Err(TransactionError::Invalid(
                        "aft bulletin commitment height must be non-zero".into(),
                    ));
                }
                if bulletin.bulletin_root == [0u8; 32] {
                    return Err(TransactionError::Invalid(
                        "aft bulletin commitment root must be non-zero".into(),
                    ));
                }
                state.insert(
                    &aft_bulletin_commitment_key(bulletin.height),
                    &codec::to_bytes_canonical(&bulletin)
                        .map_err(TransactionError::Serialization)?,
                )?;
                Ok(())
            }
            "publish_aft_bulletin_entry@v1" => {
                let entry: BulletinSurfaceEntry = codec::from_bytes_canonical(params)?;
                if entry.height == 0 || entry.tx_hash == [0u8; 32] {
                    return Err(TransactionError::Invalid(
                        "aft bulletin entry requires non-zero height and tx hash".into(),
                    ));
                }
                state.insert(
                    &aft_bulletin_entry_key(entry.height, &entry.tx_hash),
                    &codec::to_bytes_canonical(&entry).map_err(TransactionError::Serialization)?,
                )?;
                Ok(())
            }
            "publish_aft_bulletin_availability_certificate@v1" => {
                let certificate: BulletinAvailabilityCertificate =
                    codec::from_bytes_canonical(params)?;
                if certificate.height == 0
                    || certificate.bulletin_commitment_hash == [0u8; 32]
                    || certificate.recoverability_root == [0u8; 32]
                {
                    return Err(TransactionError::Invalid(
                        "aft bulletin availability certificate requires non-zero height and roots"
                            .into(),
                    ));
                }
                state.insert(
                    &aft_bulletin_availability_certificate_key(certificate.height),
                    &codec::to_bytes_canonical(&certificate)
                        .map_err(TransactionError::Serialization)?,
                )?;
                Ok(())
            }
            "publish_aft_canonical_order_artifact_bundle@v1" => {
                let bundle: CanonicalOrderPublicationBundle = codec::from_bytes_canonical(params)?;
                let bulletin_close =
                    verify_canonical_order_publication_bundle(&bundle).map_err(TransactionError::Invalid)?;
                if bundle.canonical_order_certificate.omission_proofs.is_empty()
                    && Self::load_canonical_order_abort(state, bundle.canonical_order_certificate.height)?
                        .is_some()
                {
                    return Err(TransactionError::Invalid(
                        "cannot admit a positive canonical-order bundle after canonical abort publication"
                            .into(),
                    ));
                }
                state.insert(
                    &aft_bulletin_commitment_key(bundle.bulletin_commitment.height),
                    &codec::to_bytes_canonical(&bundle.bulletin_commitment)
                        .map_err(TransactionError::Serialization)?,
                )?;
                for entry in &bundle.bulletin_entries {
                    state.insert(
                        &aft_bulletin_entry_key(entry.height, &entry.tx_hash),
                        &codec::to_bytes_canonical(entry)
                            .map_err(TransactionError::Serialization)?,
                    )?;
                }
                if !bundle.canonical_order_certificate.omission_proofs.is_empty() {
                    for omission in &bundle.canonical_order_certificate.omission_proofs {
                        if omission.offender_account_id == AccountId::default() {
                            return Err(TransactionError::Invalid(
                                "aft omission proof requires a non-zero accountable offender".into(),
                            ));
                        }
                        state.insert(
                            &aft_omission_proof_key(bundle.canonical_order_certificate.height, &omission.tx_hash),
                            &codec::to_bytes_canonical(omission)
                                .map_err(TransactionError::Serialization)?,
                        )?;
                        let report = Self::omission_failure_report(omission)?;
                        Self::apply_accountable_fault_report(
                            state,
                            report,
                            ctx.block_height,
                            self.config.apply_accountable_membership_updates,
                        )?;
                    }
                    let abort = Self::build_canonical_order_abort(
                        bundle.canonical_order_certificate.height,
                        CanonicalOrderAbortReason::OmissionDominated,
                        "objective omission proofs dominate the candidate canonical order",
                        Some(&bundle.canonical_order_certificate),
                        Some(&bulletin_close),
                    );
                    Self::materialize_canonical_order_abort(state, abort)?;
                    return Ok(());
                }
                state.insert(
                    &aft_bulletin_availability_certificate_key(
                        bundle.bulletin_availability_certificate.height,
                    ),
                    &codec::to_bytes_canonical(&bundle.bulletin_availability_certificate)
                        .map_err(TransactionError::Serialization)?,
                )?;
                state.insert(
                    &aft_order_certificate_key(bundle.canonical_order_certificate.height),
                    &codec::to_bytes_canonical(&bundle.canonical_order_certificate)
                        .map_err(TransactionError::Serialization)?,
                )?;
                state.insert(
                    &aft_canonical_bulletin_close_key(bundle.canonical_order_certificate.height),
                    &codec::to_bytes_canonical(&bulletin_close)
                        .map_err(TransactionError::Serialization)?,
                )?;
                Ok(())
            }
            "publish_aft_canonical_order_abort@v1" => {
                let abort: CanonicalOrderAbort = codec::from_bytes_canonical(params)?;
                if abort.height == 0 {
                    return Err(TransactionError::Invalid(
                        "aft canonical-order abort requires non-zero height".into(),
                    ));
                }
                Self::materialize_canonical_order_abort(state, abort)?;
                Ok(())
            }
            "publish_aft_canonical_collapse_object@v1" => {
                let collapse: CanonicalCollapseObject = codec::from_bytes_canonical(params)?;
                if collapse.height == 0 {
                    return Err(TransactionError::Invalid(
                        "aft canonical collapse object requires non-zero height".into(),
                    ));
                }
                if collapse.ordering.height != collapse.height {
                    return Err(TransactionError::Invalid(
                        "aft canonical collapse object ordering height must match slot height".into(),
                    ));
                }
                if collapse.transactions_root_hash == [0u8; 32]
                    || collapse.resulting_state_root_hash == [0u8; 32]
                {
                    return Err(TransactionError::Invalid(
                        "aft canonical collapse object requires non-zero transaction and state roots".into(),
                    ));
                }
                if let Some(sealing) = collapse.sealing.as_ref() {
                    if sealing.height != collapse.height {
                        return Err(TransactionError::Invalid(
                            "aft canonical collapse object sealing height must match slot height".into(),
                        ));
                    }
                }
                match collapse.ordering.kind {
                    CanonicalCollapseKind::Close => {
                        if Self::load_canonical_order_abort(state, collapse.height)?.is_some() {
                            return Err(TransactionError::Invalid(
                                "cannot publish a close-valued canonical collapse object after canonical-order abort publication".into(),
                            ));
                        }
                    }
                    CanonicalCollapseKind::Abort => {
                        state.delete(&aft_order_certificate_key(collapse.height))?;
                        state.delete(&aft_bulletin_availability_certificate_key(collapse.height))?;
                        state.delete(&aft_canonical_bulletin_close_key(collapse.height))?;
                    }
                }
                if let Some(existing) = Self::load_canonical_collapse_object(state, collapse.height)?
                {
                    let existing_has_abort = existing.ordering.kind == CanonicalCollapseKind::Abort
                        || existing
                            .sealing
                            .as_ref()
                            .map(|sealing| sealing.kind == CanonicalCollapseKind::Abort)
                            .unwrap_or(false);
                    let new_has_abort = collapse.ordering.kind == CanonicalCollapseKind::Abort
                        || collapse
                            .sealing
                            .as_ref()
                            .map(|sealing| sealing.kind == CanonicalCollapseKind::Abort)
                            .unwrap_or(false);
                    if existing != collapse && !(new_has_abort && !existing_has_abort) {
                        return Err(TransactionError::Invalid(
                            "conflicting canonical collapse object already published for height".into(),
                        ));
                    }
                    if existing == collapse {
                        return Ok(());
                    }
                }
                let previous = if collapse.height <= 1 {
                    None
                } else {
                    Self::load_canonical_collapse_object(state, collapse.height - 1)?
                };
                verify_canonical_collapse_continuity(&collapse, previous.as_ref())
                    .map_err(TransactionError::Invalid)?;
                state.insert(
                    &aft_canonical_collapse_object_key(collapse.height),
                    &codec::to_bytes_canonical(&collapse)
                        .map_err(TransactionError::Serialization)?,
                )?;
                Ok(())
            }
            "publish_aft_order_certificate@v1" => {
                let _certificate: CanonicalOrderCertificate = codec::from_bytes_canonical(params)?;
                Err(TransactionError::Invalid(
                    "publish_aft_order_certificate@v1 is retired; publish_aft_canonical_order_artifact_bundle@v1 is required for positive canonical-order admission".into(),
                ))
            }
            "report_aft_omission@v1" => {
                let omission: OmissionProof = codec::from_bytes_canonical(params)?;
                if omission.height == 0
                    || omission.tx_hash == [0u8; 32]
                    || omission.offender_account_id == AccountId::default()
                {
                    return Err(TransactionError::Invalid(
                        "aft omission proof requires non-zero height, offender, and tx hash".into(),
                    ));
                }
                state.insert(
                    &aft_omission_proof_key(omission.height, &omission.tx_hash),
                    &codec::to_bytes_canonical(&omission)
                        .map_err(TransactionError::Serialization)?,
                )?;
                let existing_certificate =
                    Self::load_canonical_order_certificate(state, omission.height)
                        .map_err(TransactionError::State)?;
                let existing_close =
                    Self::load_canonical_bulletin_close(state, omission.height)
                        .map_err(TransactionError::State)?;
                let abort = Self::build_canonical_order_abort(
                    omission.height,
                    CanonicalOrderAbortReason::OmissionDominated,
                    omission.details.clone(),
                    existing_certificate.as_ref(),
                    existing_close.as_ref(),
                );
                Self::materialize_canonical_order_abort(state, abort)?;
                let report = Self::omission_failure_report(&omission)?;
                Self::apply_accountable_fault_report(
                    state,
                    report,
                    ctx.block_height,
                    self.config.apply_accountable_membership_updates,
                )?;
                Ok(())
            }
            "anchor_guardian_checkpoint@v1" => {
                let checkpoint: GuardianLogCheckpoint = codec::from_bytes_canonical(params)?;
                state.insert(
                    &[
                        GUARDIAN_REGISTRY_CHECKPOINT_PREFIX,
                        checkpoint.log_id.as_bytes(),
                    ]
                    .concat(),
                    &codec::to_bytes_canonical(&checkpoint)
                        .map_err(TransactionError::Serialization)?,
                )?;
                Ok(())
            }
            "report_guardian_equivocation@v1" => {
                let proof: ProofOfDivergence = codec::from_bytes_canonical(params)?;
                state.insert(
                    &[
                        GUARDIAN_REGISTRY_EQUIVOCATION_PREFIX,
                        proof.offender.as_ref(),
                    ]
                    .concat(),
                    &codec::to_bytes_canonical(&proof).map_err(TransactionError::Serialization)?,
                )?;
                Ok(())
            }
            "report_guardian_witness_fault@v1" => {
                let evidence: GuardianWitnessFaultEvidence = codec::from_bytes_canonical(params)?;
                state.insert(
                    &guardian_registry_witness_fault_key(&evidence.evidence_id),
                    &codec::to_bytes_canonical(&evidence)
                        .map_err(TransactionError::Serialization)?,
                )?;
                Ok(())
            }
            _ => Err(TransactionError::Unsupported(format!(
                "GuardianRegistry does not support method '{}'",
                method
            ))),
        }
    }
}

#[async_trait]
impl UpgradableService for GuardianRegistry {
    async fn prepare_upgrade(&self, _new_module_wasm: &[u8]) -> Result<Vec<u8>, UpgradeError> {
        Ok(Vec::new())
    }

    async fn complete_upgrade(&self, _snapshot: &[u8]) -> Result<(), UpgradeError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ioi_api::services::access::ServiceDirectory;
    use ioi_api::state::StateScanIter;
    use ioi_api::transaction::context::TxContext;
    use ioi_types::app::{
        aft_bulletin_availability_certificate_key, aft_bulletin_commitment_key,
        aft_bulletin_entry_key, aft_canonical_bulletin_close_key,
        aft_canonical_collapse_object_key,
        aft_canonical_order_abort_key, aft_omission_proof_key, aft_order_certificate_key,
        build_bulletin_surface_entries,
        build_canonical_bulletin_close, build_committed_surface_canonical_order_certificate,
        canonical_asymptote_observer_canonical_close_hash,
        canonical_transaction_root_from_hashes, canonicalize_transactions_for_header,
        derive_canonical_collapse_object, read_validator_sets, write_validator_sets,
        guardian_registry_observer_canonical_abort_key,
        guardian_registry_observer_canonical_close_key,
        guardian_registry_observer_challenge_commitment_key,
        guardian_registry_observer_challenge_key,
        guardian_registry_observer_transcript_commitment_key,
        guardian_registry_observer_transcript_key,
        guardian_registry_effect_nullifier_key, guardian_registry_effect_verifier_key,
        guardian_registry_log_key, guardian_registry_sealed_effect_key, AccountId,
        AsymptoteObserverAssignment, AsymptoteObserverCanonicalAbort,
        AsymptoteObserverCanonicalClose,
        AsymptoteObserverChallenge, AsymptoteObserverChallengeCommitment,
        AsymptoteObserverChallengeKind, AsymptoteObserverSealingMode,
        AsymptoteObserverObservationRequest,
        AsymptoteObserverStatement, AsymptoteObserverTranscript,
        AsymptoteObserverTranscriptCommitment, AsymptoteObserverVerdict,
        BulletinAvailabilityCertificate, BulletinCommitment, BulletinSurfaceEntry,
        CanonicalBulletinClose, CanonicalCollapseObject, CanonicalOrderAbort,
        CanonicalOrderAbortReason, CanonicalOrderCertificate, CanonicalOrderProof,
        CanonicalOrderProofSystem, CanonicalOrderPublicationBundle, ChainId, ChainTransaction,
        CollapseState, EffectProofSystem, EffectProofVerifierDescriptor, FinalityTier,
        GuardianCommitteeMember,
        GuardianQuorumCertificate, GuardianTransparencyLogDescriptor,
        GuardianWitnessEpochSeed, OmissionProof, QuorumCertificate, SealedEffectClass,
        SealedEffectRecord, SealedFinalityProof, SignHeader, SignatureProof, SignatureSuite,
        StateRoot,
        SystemPayload, SystemTransaction, ValidatorSetV1, ValidatorSetsV1, ValidatorV1,
    };
    use ioi_types::keys::{EVIDENCE_REGISTRY_KEY, QUARANTINED_VALIDATORS_KEY, VALIDATOR_SET_KEY};
    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::Arc;

    #[derive(Default)]
    struct MockState {
        data: BTreeMap<Vec<u8>, Vec<u8>>,
    }

    impl StateAccess for MockState {
        fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StateError> {
            Ok(self.data.get(key).cloned())
        }

        fn insert(&mut self, key: &[u8], value: &[u8]) -> Result<(), StateError> {
            self.data.insert(key.to_vec(), value.to_vec());
            Ok(())
        }

        fn delete(&mut self, key: &[u8]) -> Result<(), StateError> {
            self.data.remove(key);
            Ok(())
        }

        fn batch_set(&mut self, updates: &[(Vec<u8>, Vec<u8>)]) -> Result<(), StateError> {
            for (key, value) in updates {
                self.insert(key, value)?;
            }
            Ok(())
        }

        fn batch_get(&self, keys: &[Vec<u8>]) -> Result<Vec<Option<Vec<u8>>>, StateError> {
            keys.iter().map(|key| self.get(key)).collect()
        }

        fn batch_apply(
            &mut self,
            inserts: &[(Vec<u8>, Vec<u8>)],
            deletes: &[Vec<u8>],
        ) -> Result<(), StateError> {
            for key in deletes {
                self.delete(key)?;
            }
            for (key, value) in inserts {
                self.insert(key, value)?;
            }
            Ok(())
        }

        fn prefix_scan(&self, prefix: &[u8]) -> Result<StateScanIter<'_>, StateError> {
            let rows: Vec<_> = self
                .data
                .iter()
                .filter(|(key, _)| key.starts_with(prefix))
                .map(|(key, value)| Ok((Arc::from(key.as_slice()), Arc::from(value.as_slice()))))
                .collect();
            Ok(Box::new(rows.into_iter()))
        }
    }

    fn with_ctx<F>(f: F)
    where
        F: FnOnce(&mut TxContext<'_>),
    {
        let services = ServiceDirectory::new(Vec::new());
        let mut ctx = TxContext {
            block_height: 42,
            block_timestamp: 1_750_000_000_000_000_000,
            chain_id: ChainId(1),
            signer_account_id: AccountId([7u8; 32]),
            services: &services,
            simulation: false,
            is_internal: false,
        };
        f(&mut ctx);
    }

    fn run_async<F: std::future::Future<Output = T>, T>(future: F) -> T {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
            .block_on(future)
    }

    fn production_registry() -> GuardianRegistry {
        GuardianRegistry::new(GuardianRegistryParams {
            enabled: true,
            ..Default::default()
        })
    }

    fn production_registry_without_accountable_membership_updates() -> GuardianRegistry {
        GuardianRegistry::new(GuardianRegistryParams {
            enabled: true,
            apply_accountable_membership_updates: false,
            ..Default::default()
        })
    }

    fn validator(account: u8, weight: u128) -> ValidatorV1 {
        ValidatorV1 {
            account_id: AccountId([account; 32]),
            weight,
            consensus_key: Default::default(),
        }
    }

    fn validator_sets(validators: &[(u8, u128)]) -> ValidatorSetsV1 {
        let entries = validators
            .iter()
            .map(|(account, weight)| validator(*account, *weight))
            .collect::<Vec<_>>();
        ValidatorSetsV1 {
            current: ValidatorSetV1 {
                effective_from_height: 1,
                total_weight: entries.iter().map(|validator| validator.weight).sum(),
                validators: entries,
            },
            next: None,
        }
    }

    fn member(
        member_id: &str,
        provider: &str,
        region: &str,
        host_class: &str,
        key_authority_kind: ioi_types::app::KeyAuthorityKind,
    ) -> GuardianCommitteeMember {
        GuardianCommitteeMember {
            member_id: member_id.to_string(),
            signature_suite: SignatureSuite::BLS12_381,
            public_key: vec![1, 2, 3, member_id.len() as u8],
            endpoint: Some(format!("https://{}.example", member_id)),
            provider: Some(provider.to_string()),
            region: Some(region.to_string()),
            host_class: Some(host_class.to_string()),
            key_authority_kind: Some(key_authority_kind),
        }
    }

    #[test]
    fn rejects_unsafe_odd_sized_guardian_committee_under_production_policy() {
        let registry = production_registry();
        let manifest = GuardianCommitteeManifest {
            validator_account_id: AccountId([1u8; 32]),
            epoch: 7,
            threshold: 3,
            members: vec![
                member(
                    "a",
                    "aws",
                    "us-east-1",
                    "x86",
                    ioi_types::app::KeyAuthorityKind::CloudKms,
                ),
                member(
                    "b",
                    "gcp",
                    "us-west-1",
                    "arm",
                    ioi_types::app::KeyAuthorityKind::Tpm2,
                ),
                member(
                    "c",
                    "azure",
                    "eu-west-1",
                    "metal",
                    ioi_types::app::KeyAuthorityKind::Pkcs11,
                ),
                member(
                    "d",
                    "aws",
                    "eu-central-1",
                    "arm64",
                    ioi_types::app::KeyAuthorityKind::CloudKms,
                ),
                member(
                    "e",
                    "gcp",
                    "ap-southeast-1",
                    "x86_64",
                    ioi_types::app::KeyAuthorityKind::Tpm2,
                ),
            ],
            measurement_profile_root: [1u8; 32],
            policy_hash: [2u8; 32],
            transparency_log_id: "guardian-log".into(),
        };

        let mut state = MockState::default();
        with_ctx(|ctx| {
            let err = run_async(registry.handle_service_call(
                &mut state,
                "register_guardian_committee@v1",
                &codec::to_bytes_canonical(&manifest).unwrap(),
                ctx,
            ))
            .unwrap_err();
            assert!(err.to_string().contains("even-sized"));
        });
    }

    #[test]
    fn registers_guardian_transparency_log_descriptor() {
        let registry = GuardianRegistry::new(Default::default());
        let descriptor = GuardianTransparencyLogDescriptor {
            log_id: "guardian-log".into(),
            signature_suite: SignatureSuite::ED25519,
            public_key: vec![1, 2, 3],
        };
        let mut state = MockState::default();

        with_ctx(|ctx| {
            run_async(registry.handle_service_call(
                &mut state,
                "register_guardian_transparency_log@v1",
                &codec::to_bytes_canonical(&descriptor).unwrap(),
                ctx,
            ))
            .unwrap();
        });

        let stored = state
            .get(&guardian_registry_log_key(&descriptor.log_id))
            .unwrap()
            .expect("log descriptor stored");
        let restored: GuardianTransparencyLogDescriptor =
            codec::from_bytes_canonical(&stored).unwrap();
        assert_eq!(restored, descriptor);
    }

    #[test]
    fn registering_witness_committee_updates_active_set_and_seed() {
        let registry = GuardianRegistry::new(GuardianRegistryParams {
            enabled: true,
            minimum_committee_size: 1,
            minimum_witness_committee_size: 1,
            minimum_provider_diversity: 1,
            minimum_region_diversity: 1,
            minimum_host_class_diversity: 1,
            minimum_backend_diversity: 1,
            require_even_committee_sizes: false,
            require_checkpoint_anchoring: true,
            max_checkpoint_staleness_ms: 120_000,
            max_committee_outage_members: 0,
            asymptote_required_witness_strata: vec!["stratum-a".into()],
            asymptote_escalation_witness_strata: vec!["stratum-a".into()],
            asymptote_high_risk_effect_tier: ioi_types::app::FinalityTier::SealedFinal,
            apply_accountable_membership_updates: true,
        });
        let manifest = GuardianWitnessCommitteeManifest {
            committee_id: "witness-a".into(),
            stratum_id: "stratum-a".into(),
            epoch: 11,
            threshold: 1,
            members: vec![member(
                "w1",
                "aws",
                "us-east-1",
                "arm",
                ioi_types::app::KeyAuthorityKind::CloudKms,
            )],
            policy_hash: [3u8; 32],
            transparency_log_id: "witness-log".into(),
        };
        let seed = GuardianWitnessEpochSeed {
            epoch: 11,
            seed: [9u8; 32],
            checkpoint_interval_blocks: 3,
            max_reassignment_depth: 2,
        };

        let mut state = MockState::default();
        with_ctx(|ctx| {
            run_async(registry.handle_service_call(
                &mut state,
                "register_guardian_witness_committee@v1",
                &codec::to_bytes_canonical(&manifest).unwrap(),
                ctx,
            ))
            .unwrap();
            run_async(registry.handle_service_call(
                &mut state,
                "publish_witness_epoch_seed@v1",
                &codec::to_bytes_canonical(&seed).unwrap(),
                ctx,
            ))
            .unwrap();
        });

        let active_set_bytes = state
            .get(&guardian_registry_witness_set_key(11))
            .expect("active set lookup")
            .expect("active set stored");
        let active_set: GuardianWitnessSet =
            codec::from_bytes_canonical(&active_set_bytes).unwrap();
        assert_eq!(active_set.epoch, 11);
        assert_eq!(active_set.manifest_hashes.len(), 1);
        assert_eq!(active_set.checkpoint_interval_blocks, 3);

        let seed_bytes = state
            .get(&guardian_registry_witness_seed_key(11))
            .expect("seed lookup")
            .expect("seed stored");
        let stored_seed: GuardianWitnessEpochSeed =
            codec::from_bytes_canonical(&seed_bytes).unwrap();
        assert_eq!(stored_seed.seed, [9u8; 32]);
        assert_eq!(stored_seed.max_reassignment_depth, 2);
    }

    #[test]
    fn registering_effect_verifier_and_recording_sealed_effect_persists_both_keys() {
        let registry = production_registry();
        let verifier = EffectProofVerifierDescriptor {
            verifier_id: "aft-http-egress-hash-binding-v1".into(),
            effect_class: SealedEffectClass::HttpEgress,
            proof_system: EffectProofSystem::HashBindingV1,
            verifying_key_hash: [21u8; 32],
            enabled: true,
        };
        let record = SealedEffectRecord {
            nullifier: [22u8; 32],
            intent_hash: [23u8; 32],
            epoch: 7,
            effect_class: SealedEffectClass::HttpEgress,
            verifier_id: verifier.verifier_id.clone(),
            seal_hash: [24u8; 32],
        };

        let mut state = MockState::default();
        with_ctx(|ctx| {
            run_async(registry.handle_service_call(
                &mut state,
                "register_effect_proof_verifier@v1",
                &codec::to_bytes_canonical(&verifier).unwrap(),
                ctx,
            ))
            .unwrap();
            run_async(registry.handle_service_call(
                &mut state,
                "record_sealed_effect@v1",
                &codec::to_bytes_canonical(&record).unwrap(),
                ctx,
            ))
            .unwrap();
        });

        let stored_verifier = state
            .get(&guardian_registry_effect_verifier_key(
                &verifier.verifier_id,
            ))
            .unwrap()
            .expect("effect verifier stored");
        let restored_verifier: EffectProofVerifierDescriptor =
            codec::from_bytes_canonical(&stored_verifier).unwrap();
        assert_eq!(restored_verifier, verifier);

        let nullifier_record = state
            .get(&guardian_registry_effect_nullifier_key(&record.nullifier))
            .unwrap()
            .expect("sealed effect nullifier record stored");
        let sealed_effect_record = state
            .get(&guardian_registry_sealed_effect_key(&record.intent_hash))
            .unwrap()
            .expect("sealed effect record stored");
        let restored_nullifier_record: SealedEffectRecord =
            codec::from_bytes_canonical(&nullifier_record).unwrap();
        let restored_effect_record: SealedEffectRecord =
            codec::from_bytes_canonical(&sealed_effect_record).unwrap();
        assert_eq!(restored_nullifier_record, record);
        assert_eq!(restored_effect_record, record);
    }

    #[test]
    fn publishing_aft_canonical_order_artifact_bundle_persists_registry_state() {
        let registry = production_registry();
        let base_header = ioi_types::app::BlockHeader {
            height: 9,
            view: 2,
            parent_hash: [11u8; 32],
            parent_state_root: StateRoot(vec![1u8; 32]),
            state_root: StateRoot(vec![2u8; 32]),
            transactions_root: Vec::new(),
            timestamp: 1_760_000_111,
            timestamp_ms: 1_760_000_111_000,
            gas_used: 0,
            validator_set: Vec::new(),
            producer_account_id: AccountId([12u8; 32]),
            producer_key_suite: SignatureSuite::ED25519,
            producer_pubkey_hash: [13u8; 32],
            producer_pubkey: Vec::new(),
            signature: Vec::new(),
            oracle_counter: 0,
            oracle_trace_hash: [0u8; 32],
            parent_qc: QuorumCertificate::default(),
            previous_canonical_collapse_commitment_hash: [0u8; 32],
            canonical_collapse_extension_certificate: None,
            guardian_certificate: None,
            sealed_finality_proof: None,
            canonical_order_certificate: None,
            timeout_certificate: None,
        };
        let tx_one = ChainTransaction::System(Box::new(SystemTransaction {
            header: SignHeader {
                account_id: AccountId([31u8; 32]),
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
                account_id: AccountId([32u8; 32]),
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

        let ordered_transactions =
            canonicalize_transactions_for_header(&base_header, &[tx_one, tx_two]).unwrap();
        let tx_hashes: Vec<[u8; 32]> = ordered_transactions
            .iter()
            .map(|tx| tx.hash().unwrap())
            .collect();
        let mut header = base_header;
        header.transactions_root = canonical_transaction_root_from_hashes(&tx_hashes).unwrap();
        let mut certificate =
            build_committed_surface_canonical_order_certificate(&header, &ordered_transactions)
                .unwrap();
        let omission = OmissionProof {
            height: header.height,
            offender_account_id: AccountId([41u8; 32]),
            tx_hash: [42u8; 32],
            bulletin_root: certificate.bulletin_commitment.bulletin_root,
            details: "tx omitted from canonical order".into(),
        };
        certificate.omission_proofs = vec![omission.clone()];
        let bundle = CanonicalOrderPublicationBundle {
            bulletin_commitment: certificate.bulletin_commitment.clone(),
            bulletin_entries: build_bulletin_surface_entries(header.height, &ordered_transactions)
                .unwrap(),
            bulletin_availability_certificate: certificate
                .bulletin_availability_certificate
                .clone(),
            canonical_order_certificate: certificate.clone(),
        };

        let mut state = MockState::default();
        with_ctx(|ctx| {
            run_async(registry.handle_service_call(
                &mut state,
                "publish_aft_canonical_order_artifact_bundle@v1",
                &codec::to_bytes_canonical(&bundle).unwrap(),
                ctx,
            ))
            .unwrap();
        });

        let stored_bulletin = state
            .get(&aft_bulletin_commitment_key(header.height))
            .unwrap()
            .expect("bulletin stored");
        let restored_bulletin: BulletinCommitment =
            codec::from_bytes_canonical(&stored_bulletin).unwrap();
        assert_eq!(restored_bulletin, bundle.bulletin_commitment);

        let stored_entry = state
            .get(&aft_bulletin_entry_key(header.height, &bundle.bulletin_entries[0].tx_hash))
            .unwrap()
            .expect("bulletin entry stored");
        let restored_entry: BulletinSurfaceEntry = codec::from_bytes_canonical(&stored_entry).unwrap();
        assert_eq!(restored_entry, bundle.bulletin_entries[0]);

        let stored_availability = state
            .get(&aft_bulletin_availability_certificate_key(header.height))
            .unwrap()
            .expect("bulletin availability certificate stored");
        let restored_availability: BulletinAvailabilityCertificate =
            codec::from_bytes_canonical(&stored_availability).unwrap();
        assert_eq!(restored_availability, bundle.bulletin_availability_certificate);

        let stored_certificate = state
            .get(&aft_order_certificate_key(header.height))
            .unwrap()
            .expect("order certificate stored");
        let restored_certificate: CanonicalOrderCertificate =
            codec::from_bytes_canonical(&stored_certificate).unwrap();
        assert_eq!(restored_certificate, certificate);

        let stored_close = state
            .get(&aft_canonical_bulletin_close_key(header.height))
            .unwrap()
            .expect("canonical bulletin close stored");
        let restored_close: CanonicalBulletinClose =
            codec::from_bytes_canonical(&stored_close).unwrap();
        assert_eq!(
            restored_close,
            build_canonical_bulletin_close(
                &bundle.bulletin_commitment,
                &bundle.bulletin_availability_certificate,
            )
            .unwrap()
        );

        let stored_omission = state
            .get(&aft_omission_proof_key(header.height, &omission.tx_hash))
            .unwrap()
            .expect("omission stored");
        let restored_omission: OmissionProof = codec::from_bytes_canonical(&stored_omission).unwrap();
        assert_eq!(restored_omission, omission);
    }

    #[test]
    fn extracting_published_bulletin_surface_returns_canonical_entries() {
        let registry = production_registry();
        let base_header = ioi_types::app::BlockHeader {
            height: 17,
            view: 3,
            parent_hash: [19u8; 32],
            parent_state_root: StateRoot(vec![1u8; 32]),
            state_root: StateRoot(vec![2u8; 32]),
            transactions_root: Vec::new(),
            timestamp: 1_760_000_123,
            timestamp_ms: 1_760_000_123_000,
            gas_used: 0,
            validator_set: Vec::new(),
            producer_account_id: AccountId([24u8; 32]),
            producer_key_suite: SignatureSuite::ED25519,
            producer_pubkey_hash: [25u8; 32],
            producer_pubkey: Vec::new(),
            signature: Vec::new(),
            oracle_counter: 0,
            oracle_trace_hash: [0u8; 32],
            parent_qc: QuorumCertificate::default(),
            previous_canonical_collapse_commitment_hash: [0u8; 32],
            canonical_collapse_extension_certificate: None,
            guardian_certificate: None,
            sealed_finality_proof: None,
            canonical_order_certificate: None,
            timeout_certificate: None,
        };
        let tx_one = ChainTransaction::System(Box::new(SystemTransaction {
            header: SignHeader {
                account_id: AccountId([31u8; 32]),
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
                account_id: AccountId([32u8; 32]),
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

        let ordered_transactions =
            canonicalize_transactions_for_header(&base_header, &[tx_one, tx_two]).unwrap();
        let tx_hashes: Vec<[u8; 32]> = ordered_transactions
            .iter()
            .map(|tx| tx.hash().unwrap())
            .collect();
        let mut header = base_header;
        header.transactions_root = canonical_transaction_root_from_hashes(&tx_hashes).unwrap();

        let certificate =
            build_committed_surface_canonical_order_certificate(&header, &ordered_transactions)
                .unwrap();
        let entries = build_bulletin_surface_entries(header.height, &ordered_transactions).unwrap();
        let bundle = CanonicalOrderPublicationBundle {
            bulletin_commitment: certificate.bulletin_commitment.clone(),
            bulletin_entries: entries.clone(),
            bulletin_availability_certificate: certificate
                .bulletin_availability_certificate
                .clone(),
            canonical_order_certificate: certificate,
        };

        let mut state = MockState::default();
        with_ctx(|ctx| {
            run_async(registry.handle_service_call(
                &mut state,
                "publish_aft_canonical_order_artifact_bundle@v1",
                &codec::to_bytes_canonical(&bundle).unwrap(),
                ctx,
            ))
            .unwrap();
        });

        let extracted = GuardianRegistry::extract_published_bulletin_surface(&state, header.height)
            .unwrap()
            .expect("canonical bulletin surface extracted");
        assert_eq!(extracted, entries);
    }

    #[test]
    fn publishing_aft_canonical_order_artifact_bundle_persists_extractable_close_surface() {
        let registry = production_registry();
        let base_header = ioi_types::app::BlockHeader {
            height: 27,
            view: 2,
            parent_hash: [11u8; 32],
            parent_state_root: StateRoot(vec![1u8; 32]),
            state_root: StateRoot(vec![2u8; 32]),
            transactions_root: Vec::new(),
            timestamp: 1_760_000_333,
            timestamp_ms: 1_760_000_333_000,
            gas_used: 0,
            validator_set: Vec::new(),
            producer_account_id: AccountId([21u8; 32]),
            producer_key_suite: SignatureSuite::ED25519,
            producer_pubkey_hash: [22u8; 32],
            producer_pubkey: Vec::new(),
            signature: Vec::new(),
            oracle_counter: 0,
            oracle_trace_hash: [0u8; 32],
            parent_qc: QuorumCertificate::default(),
            previous_canonical_collapse_commitment_hash: [0u8; 32],
            canonical_collapse_extension_certificate: None,
            guardian_certificate: None,
            sealed_finality_proof: None,
            canonical_order_certificate: None,
            timeout_certificate: None,
        };
        let tx_one = ChainTransaction::System(Box::new(SystemTransaction {
            header: SignHeader {
                account_id: AccountId([31u8; 32]),
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
                account_id: AccountId([32u8; 32]),
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

        let ordered_transactions =
            canonicalize_transactions_for_header(&base_header, &[tx_one, tx_two]).unwrap();
        let tx_hashes: Vec<[u8; 32]> = ordered_transactions
            .iter()
            .map(|tx| tx.hash().unwrap())
            .collect();
        let mut header = base_header;
        header.transactions_root = canonical_transaction_root_from_hashes(&tx_hashes).unwrap();
        let certificate =
            build_committed_surface_canonical_order_certificate(&header, &ordered_transactions)
                .unwrap();
        let bundle = CanonicalOrderPublicationBundle {
            bulletin_commitment: certificate.bulletin_commitment.clone(),
            bulletin_entries: build_bulletin_surface_entries(header.height, &ordered_transactions)
                .unwrap(),
            bulletin_availability_certificate: certificate
                .bulletin_availability_certificate
                .clone(),
            canonical_order_certificate: certificate.clone(),
        };

        let mut state = MockState::default();
        with_ctx(|ctx| {
            run_async(registry.handle_service_call(
                &mut state,
                "publish_aft_canonical_order_artifact_bundle@v1",
                &codec::to_bytes_canonical(&bundle).unwrap(),
                ctx,
            ))
            .unwrap();
        });

        let extracted = GuardianRegistry::extract_published_bulletin_surface(&state, header.height)
            .unwrap()
            .expect("extractable close surface");
        assert_eq!(extracted, bundle.bulletin_entries);
        let required = GuardianRegistry::require_published_bulletin_surface(&state, header.height)
            .expect("strict extraction surface");
        assert_eq!(required, bundle.bulletin_entries);

        let stored_close = state
            .get(&aft_canonical_bulletin_close_key(header.height))
            .unwrap()
            .expect("canonical bulletin close stored");
        let restored_close: CanonicalBulletinClose =
            codec::from_bytes_canonical(&stored_close).unwrap();
        assert_eq!(
            restored_close,
            build_canonical_bulletin_close(
                &bundle.bulletin_commitment,
                &bundle.bulletin_availability_certificate,
            )
            .unwrap()
        );
    }

    #[test]
    fn publishing_aft_order_certificate_legacy_method_is_rejected() {
        let registry = production_registry();
        let bulletin = BulletinCommitment {
            height: 41,
            cutoff_timestamp_ms: 1_760_000_444,
            bulletin_root: [71u8; 32],
            entry_count: 2,
        };
        let availability_certificate = BulletinAvailabilityCertificate {
            height: 41,
            bulletin_commitment_hash: ioi_types::app::canonical_bulletin_commitment_hash(&bulletin)
                .unwrap(),
            recoverability_root: [72u8; 32],
        };
        let certificate = CanonicalOrderCertificate {
            height: 41,
            bulletin_commitment: bulletin.clone(),
            bulletin_availability_certificate: availability_certificate.clone(),
            randomness_beacon: [73u8; 32],
            ordered_transactions_root_hash: [74u8; 32],
            resulting_state_root_hash: [75u8; 32],
            proof: CanonicalOrderProof {
                proof_system: CanonicalOrderProofSystem::HashBindingV1,
                public_inputs_hash: [76u8; 32],
                proof_bytes: vec![77u8; 32],
            },
            omission_proofs: Vec::new(),
        };

        let mut state = MockState::default();
        with_ctx(|ctx| {
            run_async(registry.handle_service_call(
                &mut state,
                "publish_aft_bulletin_commitment@v1",
                &codec::to_bytes_canonical(&bulletin).unwrap(),
                ctx,
            ))
            .unwrap();
            run_async(registry.handle_service_call(
                &mut state,
                "publish_aft_bulletin_availability_certificate@v1",
                &codec::to_bytes_canonical(&availability_certificate).unwrap(),
                ctx,
            ))
            .unwrap();
            let err = run_async(registry.handle_service_call(
                &mut state,
                "publish_aft_order_certificate@v1",
                &codec::to_bytes_canonical(&certificate).unwrap(),
                ctx,
            ))
            .unwrap_err();
            assert!(err
                .to_string()
                .contains("publish_aft_order_certificate@v1 is retired"));
        });
    }

    #[test]
    fn publishing_aft_canonical_order_abort_persists_registry_state() {
        let registry = production_registry();
        let abort = CanonicalOrderAbort {
            height: 44,
            reason: CanonicalOrderAbortReason::InvalidProofBinding,
            details: "proof-carried canonical-order certificate failed binding verification".into(),
            bulletin_commitment_hash: [101u8; 32],
            bulletin_availability_certificate_hash: [102u8; 32],
            bulletin_close_hash: [103u8; 32],
            canonical_order_certificate_hash: [104u8; 32],
        };

        let mut state = MockState::default();
        with_ctx(|ctx| {
            run_async(registry.handle_service_call(
                &mut state,
                "publish_aft_canonical_order_abort@v1",
                &codec::to_bytes_canonical(&abort).unwrap(),
                ctx,
            ))
            .unwrap();
        });

        let stored_abort = state
            .get(&aft_canonical_order_abort_key(abort.height))
            .unwrap()
            .expect("canonical-order abort stored");
        let restored_abort: CanonicalOrderAbort = codec::from_bytes_canonical(&stored_abort).unwrap();
        assert_eq!(restored_abort, abort);
    }

    #[test]
    fn publishing_aft_canonical_collapse_object_persists_registry_state() {
        let registry = production_registry();
        let base_header = ioi_types::app::BlockHeader {
            height: 46,
            view: 2,
            parent_hash: [121u8; 32],
            parent_state_root: StateRoot(vec![1u8; 32]),
            state_root: StateRoot(vec![2u8; 32]),
            transactions_root: Vec::new(),
            timestamp: 1_760_000_888,
            timestamp_ms: 1_760_000_888_000,
            gas_used: 0,
            validator_set: Vec::new(),
            producer_account_id: AccountId([122u8; 32]),
            producer_key_suite: SignatureSuite::ED25519,
            producer_pubkey_hash: [123u8; 32],
            producer_pubkey: Vec::new(),
            signature: Vec::new(),
            oracle_counter: 0,
            oracle_trace_hash: [0u8; 32],
            parent_qc: QuorumCertificate::default(),
            previous_canonical_collapse_commitment_hash: [0u8; 32],
            canonical_collapse_extension_certificate: None,
            guardian_certificate: None,
            sealed_finality_proof: None,
            canonical_order_certificate: None,
            timeout_certificate: None,
        };
        let tx_one = ChainTransaction::System(Box::new(SystemTransaction {
            header: SignHeader {
                account_id: AccountId([124u8; 32]),
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
                account_id: AccountId([125u8; 32]),
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
        let ordered_transactions =
            canonicalize_transactions_for_header(&base_header, &[tx_one, tx_two]).unwrap();
        let tx_hashes: Vec<[u8; 32]> = ordered_transactions
            .iter()
            .map(|tx| tx.hash().unwrap())
            .collect();
        let mut header = base_header;
        header.transactions_root = canonical_transaction_root_from_hashes(&tx_hashes).unwrap();
        header.canonical_order_certificate = Some(
            build_committed_surface_canonical_order_certificate(&header, &ordered_transactions)
                .unwrap(),
        );
        let previous = CanonicalCollapseObject {
            height: header.height - 1,
            previous_canonical_collapse_commitment_hash: [0u8; 32],
            continuity_accumulator_hash: [0u8; 32],
            continuity_recursive_proof: Default::default(),
            ordering: Default::default(),
            sealing: None,
            transactions_root_hash: [201u8; 32],
            resulting_state_root_hash: [202u8; 32],
        };
        let collapse = ioi_types::app::derive_canonical_collapse_object_with_previous(
            &header,
            &ordered_transactions,
            Some(&previous),
        )
        .expect("collapse");

        let mut state = MockState::default();
        state.insert(
            &aft_canonical_collapse_object_key(previous.height),
            &codec::to_bytes_canonical(&previous).unwrap(),
        )
        .unwrap();
        with_ctx(|ctx| {
            run_async(registry.handle_service_call(
                &mut state,
                "publish_aft_canonical_collapse_object@v1",
                &codec::to_bytes_canonical(&collapse).unwrap(),
                ctx,
            ))
            .unwrap();
        });

        let stored = state
            .get(&aft_canonical_collapse_object_key(collapse.height))
            .unwrap()
            .expect("canonical collapse object stored");
        let restored: CanonicalCollapseObject = codec::from_bytes_canonical(&stored).unwrap();
        assert_eq!(restored, collapse);
    }

    #[test]
    fn publishing_conflicting_aft_canonical_collapse_object_is_rejected() {
        let registry = production_registry();
        let previous = CanonicalCollapseObject {
            height: 46,
            previous_canonical_collapse_commitment_hash: [0u8; 32],
            continuity_accumulator_hash: [0u8; 32],
            continuity_recursive_proof: Default::default(),
            ordering: Default::default(),
            sealing: None,
            transactions_root_hash: [138u8; 32],
            resulting_state_root_hash: [139u8; 32],
        };
        let mut collapse = CanonicalCollapseObject {
            height: 47,
            previous_canonical_collapse_commitment_hash:
                ioi_types::app::canonical_collapse_commitment_hash_from_object(&previous).unwrap(),
            continuity_accumulator_hash: [0u8; 32],
            continuity_recursive_proof: Default::default(),
            ordering: ioi_types::app::CanonicalOrderingCollapse {
                height: 47,
                kind: CanonicalCollapseKind::Abort,
                ..Default::default()
            },
            sealing: None,
            transactions_root_hash: [140u8; 32],
            resulting_state_root_hash: [141u8; 32],
        };
        ioi_types::app::bind_canonical_collapse_continuity(&mut collapse, Some(&previous))
            .unwrap();
        let mut conflicting = collapse.clone();
        conflicting.resulting_state_root_hash = [142u8; 32];
        ioi_types::app::bind_canonical_collapse_continuity(&mut conflicting, Some(&previous))
            .unwrap();

        let mut state = MockState::default();
        state.insert(
            &aft_canonical_collapse_object_key(previous.height),
            &codec::to_bytes_canonical(&previous).unwrap(),
        )
        .unwrap();
        with_ctx(|ctx| {
            run_async(registry.handle_service_call(
                &mut state,
                "publish_aft_canonical_collapse_object@v1",
                &codec::to_bytes_canonical(&collapse).unwrap(),
                ctx,
            ))
            .unwrap();
            let err = run_async(registry.handle_service_call(
                &mut state,
                "publish_aft_canonical_collapse_object@v1",
                &codec::to_bytes_canonical(&conflicting).unwrap(),
                ctx,
            ))
            .unwrap_err();
            assert!(err
                .to_string()
                .contains("conflicting canonical collapse object already published"));
        });
    }

    #[test]
    fn publishing_aft_canonical_collapse_object_with_wrong_previous_hash_is_rejected() {
        let registry = production_registry();
        let previous = CanonicalCollapseObject {
            height: 46,
            previous_canonical_collapse_commitment_hash: [0u8; 32],
            continuity_accumulator_hash: [0u8; 32],
            continuity_recursive_proof: Default::default(),
            ordering: Default::default(),
            sealing: None,
            transactions_root_hash: [150u8; 32],
            resulting_state_root_hash: [151u8; 32],
        };
        let mut collapse = CanonicalCollapseObject {
            height: 47,
            previous_canonical_collapse_commitment_hash: [0xFFu8; 32],
            continuity_accumulator_hash: [0u8; 32],
            continuity_recursive_proof: Default::default(),
            ordering: ioi_types::app::CanonicalOrderingCollapse {
                height: 47,
                kind: CanonicalCollapseKind::Abort,
                ..Default::default()
            },
            sealing: None,
            transactions_root_hash: [152u8; 32],
            resulting_state_root_hash: [153u8; 32],
        };
        ioi_types::app::bind_canonical_collapse_continuity(&mut collapse, Some(&previous))
            .unwrap();
        collapse.previous_canonical_collapse_commitment_hash = [0xFFu8; 32];

        let mut state = MockState::default();
        state.insert(
            &aft_canonical_collapse_object_key(previous.height),
            &codec::to_bytes_canonical(&previous).unwrap(),
        )
        .unwrap();
        with_ctx(|ctx| {
            let err = run_async(registry.handle_service_call(
                &mut state,
                "publish_aft_canonical_collapse_object@v1",
                &codec::to_bytes_canonical(&collapse).unwrap(),
                ctx,
            ))
            .unwrap_err();
            assert!(err
                .to_string()
                .contains("canonical collapse continuity commitment hash mismatch"));
        });
    }

    #[test]
    fn publishing_aft_canonical_order_artifact_bundle_with_missing_entry_is_rejected() {
        let registry = production_registry();
        let base_header = ioi_types::app::BlockHeader {
            height: 42,
            view: 4,
            parent_hash: [81u8; 32],
            parent_state_root: StateRoot(vec![1u8; 32]),
            state_root: StateRoot(vec![2u8; 32]),
            transactions_root: Vec::new(),
            timestamp: 1_760_000_555,
            timestamp_ms: 1_760_000_555_000,
            gas_used: 0,
            validator_set: Vec::new(),
            producer_account_id: AccountId([82u8; 32]),
            producer_key_suite: SignatureSuite::ED25519,
            producer_pubkey_hash: [83u8; 32],
            producer_pubkey: Vec::new(),
            signature: Vec::new(),
            oracle_counter: 0,
            oracle_trace_hash: [0u8; 32],
            parent_qc: QuorumCertificate::default(),
            previous_canonical_collapse_commitment_hash: [0u8; 32],
            canonical_collapse_extension_certificate: None,
            guardian_certificate: None,
            sealed_finality_proof: None,
            canonical_order_certificate: None,
            timeout_certificate: None,
        };
        let tx_one = ChainTransaction::System(Box::new(SystemTransaction {
            header: SignHeader {
                account_id: AccountId([84u8; 32]),
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
                account_id: AccountId([85u8; 32]),
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

        let ordered_transactions =
            canonicalize_transactions_for_header(&base_header, &[tx_one, tx_two]).unwrap();
        let tx_hashes: Vec<[u8; 32]> = ordered_transactions
            .iter()
            .map(|tx| tx.hash().unwrap())
            .collect();
        let mut header = base_header;
        header.transactions_root = canonical_transaction_root_from_hashes(&tx_hashes).unwrap();
        let certificate =
            build_committed_surface_canonical_order_certificate(&header, &ordered_transactions)
                .unwrap();
        let mut bundle = CanonicalOrderPublicationBundle {
            bulletin_commitment: certificate.bulletin_commitment.clone(),
            bulletin_entries: build_bulletin_surface_entries(header.height, &ordered_transactions)
                .unwrap(),
            bulletin_availability_certificate: certificate
                .bulletin_availability_certificate
                .clone(),
            canonical_order_certificate: certificate.clone(),
        };
        bundle.bulletin_entries.pop();

        let mut state = MockState::default();
        with_ctx(|ctx| {
            let err = run_async(registry.handle_service_call(
                &mut state,
                "publish_aft_canonical_order_artifact_bundle@v1",
                &codec::to_bytes_canonical(&bundle).unwrap(),
                ctx,
            ))
            .unwrap_err();
            assert!(err
                .to_string()
                .contains("published bulletin surface does not rebuild the bulletin commitment"));
        });
    }

    #[test]
    fn publishing_aft_canonical_order_artifact_bundle_with_wrong_height_is_rejected() {
        let registry = production_registry();
        let base_header = ioi_types::app::BlockHeader {
            height: 43,
            view: 4,
            parent_hash: [91u8; 32],
            parent_state_root: StateRoot(vec![1u8; 32]),
            state_root: StateRoot(vec![2u8; 32]),
            transactions_root: Vec::new(),
            timestamp: 1_760_000_666,
            timestamp_ms: 1_760_000_666_000,
            gas_used: 0,
            validator_set: Vec::new(),
            producer_account_id: AccountId([92u8; 32]),
            producer_key_suite: SignatureSuite::ED25519,
            producer_pubkey_hash: [93u8; 32],
            producer_pubkey: Vec::new(),
            signature: Vec::new(),
            oracle_counter: 0,
            oracle_trace_hash: [0u8; 32],
            parent_qc: QuorumCertificate::default(),
            previous_canonical_collapse_commitment_hash: [0u8; 32],
            canonical_collapse_extension_certificate: None,
            guardian_certificate: None,
            sealed_finality_proof: None,
            canonical_order_certificate: None,
            timeout_certificate: None,
        };
        let tx_one = ChainTransaction::System(Box::new(SystemTransaction {
            header: SignHeader {
                account_id: AccountId([94u8; 32]),
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
                account_id: AccountId([95u8; 32]),
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

        let ordered_transactions =
            canonicalize_transactions_for_header(&base_header, &[tx_one, tx_two]).unwrap();
        let tx_hashes: Vec<[u8; 32]> = ordered_transactions
            .iter()
            .map(|tx| tx.hash().unwrap())
            .collect();
        let mut header = base_header;
        header.transactions_root = canonical_transaction_root_from_hashes(&tx_hashes).unwrap();
        let certificate =
            build_committed_surface_canonical_order_certificate(&header, &ordered_transactions)
                .unwrap();
        let mut bundle = CanonicalOrderPublicationBundle {
            bulletin_commitment: certificate.bulletin_commitment.clone(),
            bulletin_entries: build_bulletin_surface_entries(header.height, &ordered_transactions)
                .unwrap(),
            bulletin_availability_certificate: certificate
                .bulletin_availability_certificate
                .clone(),
            canonical_order_certificate: certificate.clone(),
        };
        bundle.bulletin_entries[0].height = header.height + 1;

        let mut state = MockState::default();
        with_ctx(|ctx| {
            let err = run_async(registry.handle_service_call(
                &mut state,
                "publish_aft_canonical_order_artifact_bundle@v1",
                &codec::to_bytes_canonical(&bundle).unwrap(),
                ctx,
            ))
            .unwrap_err();
            assert!(err
                .to_string()
                .contains("bulletin surface entries do not match the target slot height"));
        });
    }

    #[test]
    fn publishing_aft_canonical_order_artifact_bundle_after_abort_is_rejected() {
        let registry = production_registry();
        let base_header = ioi_types::app::BlockHeader {
            height: 45,
            view: 4,
            parent_hash: [111u8; 32],
            parent_state_root: StateRoot(vec![1u8; 32]),
            state_root: StateRoot(vec![2u8; 32]),
            transactions_root: Vec::new(),
            timestamp: 1_760_000_777,
            timestamp_ms: 1_760_000_777_000,
            gas_used: 0,
            validator_set: Vec::new(),
            producer_account_id: AccountId([112u8; 32]),
            producer_key_suite: SignatureSuite::ED25519,
            producer_pubkey_hash: [113u8; 32],
            producer_pubkey: Vec::new(),
            signature: Vec::new(),
            oracle_counter: 0,
            oracle_trace_hash: [0u8; 32],
            parent_qc: QuorumCertificate::default(),
            previous_canonical_collapse_commitment_hash: [0u8; 32],
            canonical_collapse_extension_certificate: None,
            guardian_certificate: None,
            sealed_finality_proof: None,
            canonical_order_certificate: None,
            timeout_certificate: None,
        };
        let tx_one = ChainTransaction::System(Box::new(SystemTransaction {
            header: SignHeader {
                account_id: AccountId([114u8; 32]),
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
                account_id: AccountId([115u8; 32]),
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

        let ordered_transactions =
            canonicalize_transactions_for_header(&base_header, &[tx_one, tx_two]).unwrap();
        let tx_hashes: Vec<[u8; 32]> = ordered_transactions
            .iter()
            .map(|tx| tx.hash().unwrap())
            .collect();
        let mut header = base_header;
        header.transactions_root = canonical_transaction_root_from_hashes(&tx_hashes).unwrap();
        let certificate =
            build_committed_surface_canonical_order_certificate(&header, &ordered_transactions)
                .unwrap();
        let bundle = CanonicalOrderPublicationBundle {
            bulletin_commitment: certificate.bulletin_commitment.clone(),
            bulletin_entries: build_bulletin_surface_entries(header.height, &ordered_transactions)
                .unwrap(),
            bulletin_availability_certificate: certificate
                .bulletin_availability_certificate
                .clone(),
            canonical_order_certificate: certificate,
        };
        let abort = CanonicalOrderAbort {
            height: header.height,
            reason: CanonicalOrderAbortReason::MissingOrderCertificate,
            details: "slot already collapsed to abort".into(),
            bulletin_commitment_hash: [116u8; 32],
            bulletin_availability_certificate_hash: [117u8; 32],
            bulletin_close_hash: [0u8; 32],
            canonical_order_certificate_hash: [0u8; 32],
        };

        let mut state = MockState::default();
        with_ctx(|ctx| {
            run_async(registry.handle_service_call(
                &mut state,
                "publish_aft_canonical_order_abort@v1",
                &codec::to_bytes_canonical(&abort).unwrap(),
                ctx,
            ))
            .unwrap();
            let err = run_async(registry.handle_service_call(
                &mut state,
                "publish_aft_canonical_order_artifact_bundle@v1",
                &codec::to_bytes_canonical(&bundle).unwrap(),
                ctx,
            ))
            .unwrap_err();
            assert!(err.to_string().contains("after canonical abort publication"));
        });
    }

    #[test]
    fn reporting_aft_omission_auto_accounts_offender_and_stages_next_epoch_eviction() {
        let registry = production_registry();
        let offender = AccountId([11u8; 32]);
        let omission = OmissionProof {
            height: 9,
            offender_account_id: offender,
            tx_hash: [51u8; 32],
            bulletin_root: [52u8; 32],
            details: "candidate order omitted an admitted transaction".into(),
        };

        let mut state = MockState::default();
        state
            .insert(
                VALIDATOR_SET_KEY,
                &write_validator_sets(&validator_sets(&[(7, 1), (11, 1), (12, 1)])).unwrap(),
            )
            .unwrap();

        with_ctx(|ctx| {
            run_async(registry.handle_service_call(
                &mut state,
                "report_aft_omission@v1",
                &codec::to_bytes_canonical(&omission).unwrap(),
                ctx,
            ))
            .unwrap();
        });

        let quarantined: BTreeSet<AccountId> = codec::from_bytes_canonical(
            &state
                .get(QUARANTINED_VALIDATORS_KEY)
                .unwrap()
                .expect("quarantine set stored"),
        )
        .unwrap();
        assert!(quarantined.contains(&offender));

        let stored_sets = read_validator_sets(
            &state
                .get(VALIDATOR_SET_KEY)
                .unwrap()
                .expect("validator sets stored"),
        )
        .unwrap();
        let next = stored_sets.next.expect("next validator set staged");
        assert_eq!(next.effective_from_height, 43);
        assert!(!next.validators.iter().any(|validator| validator.account_id == offender));

        let evidence_registry: BTreeSet<[u8; 32]> = codec::from_bytes_canonical(
            &state
                .get(EVIDENCE_REGISTRY_KEY)
                .unwrap()
                .expect("evidence registry stored"),
        )
        .unwrap();
        assert_eq!(evidence_registry.len(), 1);
    }

    #[test]
    fn publishing_aft_canonical_order_artifact_bundle_with_omission_proof_materializes_abort_without_membership_updates()
    {
        let registry = production_registry_without_accountable_membership_updates();
        let base_header = ioi_types::app::BlockHeader {
            height: 10,
            view: 2,
            parent_hash: [11u8; 32],
            parent_state_root: StateRoot(vec![1u8; 32]),
            state_root: StateRoot(vec![2u8; 32]),
            transactions_root: Vec::new(),
            timestamp: 1_760_000_211,
            timestamp_ms: 1_760_000_211_000,
            gas_used: 0,
            validator_set: Vec::new(),
            producer_account_id: AccountId([12u8; 32]),
            producer_key_suite: SignatureSuite::ED25519,
            producer_pubkey_hash: [13u8; 32],
            producer_pubkey: Vec::new(),
            signature: Vec::new(),
            oracle_counter: 0,
            oracle_trace_hash: [0u8; 32],
            parent_qc: QuorumCertificate::default(),
            previous_canonical_collapse_commitment_hash: [0u8; 32],
            canonical_collapse_extension_certificate: None,
            guardian_certificate: None,
            sealed_finality_proof: None,
            canonical_order_certificate: None,
            timeout_certificate: None,
        };
        let tx_one = ChainTransaction::System(Box::new(SystemTransaction {
            header: SignHeader {
                account_id: AccountId([31u8; 32]),
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
                account_id: AccountId([32u8; 32]),
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

        let ordered_transactions =
            canonicalize_transactions_for_header(&base_header, &[tx_one, tx_two]).unwrap();
        let tx_hashes: Vec<[u8; 32]> = ordered_transactions
            .iter()
            .map(|tx| tx.hash().unwrap())
            .collect();
        let mut header = base_header;
        header.transactions_root = canonical_transaction_root_from_hashes(&tx_hashes).unwrap();
        let mut certificate =
            build_committed_surface_canonical_order_certificate(&header, &ordered_transactions)
                .unwrap();
        let offender = AccountId([44u8; 32]);
        let omission = OmissionProof {
            height: header.height,
            offender_account_id: offender,
            tx_hash: [45u8; 32],
            bulletin_root: certificate.bulletin_commitment.bulletin_root,
            details: "bundle-carried omission remains decisive without membership penalties"
                .into(),
        };
        certificate.omission_proofs = vec![omission.clone()];
        let bundle = CanonicalOrderPublicationBundle {
            bulletin_commitment: certificate.bulletin_commitment.clone(),
            bulletin_entries: build_bulletin_surface_entries(header.height, &ordered_transactions)
                .unwrap(),
            bulletin_availability_certificate: certificate
                .bulletin_availability_certificate
                .clone(),
            canonical_order_certificate: certificate.clone(),
        };

        let mut state = MockState::default();
        state
            .insert(
                VALIDATOR_SET_KEY,
                &write_validator_sets(&validator_sets(&[(12, 1), (44, 1), (46, 1)])).unwrap(),
            )
            .unwrap();

        with_ctx(|ctx| {
            run_async(registry.handle_service_call(
                &mut state,
                "publish_aft_canonical_order_artifact_bundle@v1",
                &codec::to_bytes_canonical(&bundle).unwrap(),
                ctx,
            ))
            .unwrap();
        });

        let stored_abort: CanonicalOrderAbort = codec::from_bytes_canonical(
            &state
                .get(&aft_canonical_order_abort_key(header.height))
                .unwrap()
                .expect("order abort stored"),
        )
        .unwrap();
        assert_eq!(stored_abort.reason, CanonicalOrderAbortReason::OmissionDominated);
        assert_eq!(stored_abort.canonical_order_certificate_hash, canonical_order_certificate_hash(&certificate).unwrap());
        assert!(state.get(&aft_order_certificate_key(header.height)).unwrap().is_none());
        assert!(state
            .get(&aft_bulletin_availability_certificate_key(header.height))
            .unwrap()
            .is_none());
        assert!(state
            .get(&aft_canonical_bulletin_close_key(header.height))
            .unwrap()
            .is_none());
        assert!(state.get(QUARANTINED_VALIDATORS_KEY).unwrap().is_none());

        let stored_sets = read_validator_sets(
            &state
                .get(VALIDATOR_SET_KEY)
                .unwrap()
                .expect("validator sets stored"),
        )
        .unwrap();
        assert!(stored_sets.next.is_none());
        assert!(stored_sets
            .current
            .validators
            .iter()
            .any(|validator| validator.account_id == offender));

        let evidence_registry: BTreeSet<[u8; 32]> = codec::from_bytes_canonical(
            &state
                .get(EVIDENCE_REGISTRY_KEY)
                .unwrap()
                .expect("evidence registry stored"),
        )
        .unwrap();
        assert_eq!(evidence_registry.len(), 1);
    }

    #[test]
    fn reporting_aft_omission_remains_published_when_accountable_membership_updates_are_disabled() {
        let registry = production_registry_without_accountable_membership_updates();
        let offender = AccountId([14u8; 32]);
        let omission = OmissionProof {
            height: 10,
            offender_account_id: offender,
            tx_hash: [53u8; 32],
            bulletin_root: [54u8; 32],
            details: "negative ordering object remains decisive without membership penalties"
                .into(),
        };

        let mut state = MockState::default();
        state
            .insert(
                VALIDATOR_SET_KEY,
                &write_validator_sets(&validator_sets(&[(7, 1), (14, 1), (15, 1)])).unwrap(),
            )
            .unwrap();

        with_ctx(|ctx| {
            run_async(registry.handle_service_call(
                &mut state,
                "report_aft_omission@v1",
                &codec::to_bytes_canonical(&omission).unwrap(),
                ctx,
            ))
            .unwrap();
        });

        let stored_omission: OmissionProof = codec::from_bytes_canonical(
            &state
                .get(&aft_omission_proof_key(omission.height, &omission.tx_hash))
                .unwrap()
                .expect("omission proof stored"),
        )
        .unwrap();
        assert_eq!(stored_omission, omission);
        assert!(state.get(QUARANTINED_VALIDATORS_KEY).unwrap().is_none());

        let stored_sets = read_validator_sets(
            &state
                .get(VALIDATOR_SET_KEY)
                .unwrap()
                .expect("validator sets stored"),
        )
        .unwrap();
        assert!(stored_sets.next.is_none());
        assert!(stored_sets
            .current
            .validators
            .iter()
            .any(|validator| validator.account_id == offender));

        let evidence_registry: BTreeSet<[u8; 32]> = codec::from_bytes_canonical(
            &state
                .get(EVIDENCE_REGISTRY_KEY)
                .unwrap()
                .expect("evidence registry stored"),
        )
        .unwrap();
        assert_eq!(evidence_registry.len(), 1);
    }

    #[test]
    fn reporting_aft_omission_after_positive_ordering_artifacts_materializes_abort_dominance() {
        let registry = production_registry();
        let base_header = ioi_types::app::BlockHeader {
            height: 18,
            view: 2,
            parent_hash: [31u8; 32],
            parent_state_root: StateRoot(vec![1u8; 32]),
            state_root: StateRoot(vec![2u8; 32]),
            transactions_root: Vec::new(),
            timestamp: 1_760_000_411,
            timestamp_ms: 1_760_000_411_000,
            gas_used: 0,
            validator_set: Vec::new(),
            producer_account_id: AccountId([32u8; 32]),
            producer_key_suite: SignatureSuite::ED25519,
            producer_pubkey_hash: [33u8; 32],
            producer_pubkey: Vec::new(),
            signature: Vec::new(),
            oracle_counter: 0,
            oracle_trace_hash: [0u8; 32],
            parent_qc: QuorumCertificate::default(),
            previous_canonical_collapse_commitment_hash: [0u8; 32],
            canonical_collapse_extension_certificate: None,
            guardian_certificate: None,
            sealed_finality_proof: None,
            canonical_order_certificate: None,
            timeout_certificate: None,
        };
        let tx = ChainTransaction::System(Box::new(SystemTransaction {
            header: SignHeader {
                account_id: AccountId([34u8; 32]),
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
        let ordered_transactions = canonicalize_transactions_for_header(&base_header, &[tx]).unwrap();
        let tx_hashes: Vec<[u8; 32]> = ordered_transactions.iter().map(|tx| tx.hash().unwrap()).collect();
        let mut header = base_header;
        header.transactions_root = canonical_transaction_root_from_hashes(&tx_hashes).unwrap();
        let certificate =
            build_committed_surface_canonical_order_certificate(&header, &ordered_transactions)
                .unwrap();
        let bundle = CanonicalOrderPublicationBundle {
            bulletin_commitment: certificate.bulletin_commitment.clone(),
            bulletin_entries: build_bulletin_surface_entries(header.height, &ordered_transactions)
                .unwrap(),
            bulletin_availability_certificate: certificate
                .bulletin_availability_certificate
                .clone(),
            canonical_order_certificate: certificate.clone(),
        };
        let omission = OmissionProof {
            height: header.height,
            offender_account_id: AccountId([35u8; 32]),
            tx_hash: [36u8; 32],
            bulletin_root: certificate.bulletin_commitment.bulletin_root,
            details: "late omission dominates positive ordering artifacts".into(),
        };

        let mut state = MockState::default();
        state
            .insert(
                VALIDATOR_SET_KEY,
                &write_validator_sets(&validator_sets(&[(32, 1), (35, 1), (36, 1)])).unwrap(),
            )
            .unwrap();

        with_ctx(|ctx| {
            run_async(registry.handle_service_call(
                &mut state,
                "publish_aft_canonical_order_artifact_bundle@v1",
                &codec::to_bytes_canonical(&bundle).unwrap(),
                ctx,
            ))
            .unwrap();
            run_async(registry.handle_service_call(
                &mut state,
                "report_aft_omission@v1",
                &codec::to_bytes_canonical(&omission).unwrap(),
                ctx,
            ))
            .unwrap();
        });

        let stored_abort: CanonicalOrderAbort = codec::from_bytes_canonical(
            &state
                .get(&aft_canonical_order_abort_key(header.height))
                .unwrap()
                .expect("order abort stored"),
        )
        .unwrap();
        assert_eq!(stored_abort.reason, CanonicalOrderAbortReason::OmissionDominated);
        assert!(state.get(&aft_order_certificate_key(header.height)).unwrap().is_none());
        assert!(state
            .get(&aft_bulletin_availability_certificate_key(header.height))
            .unwrap()
            .is_none());
        assert!(state
            .get(&aft_canonical_bulletin_close_key(header.height))
            .unwrap()
            .is_none());
    }

    #[test]
    fn transcript_mismatch_challenge_penalizes_producer_not_observer() {
        let registry = production_registry();
        let producer = AccountId([21u8; 32]);
        let observer = AccountId([22u8; 32]);
        let assignment = AsymptoteObserverAssignment {
            epoch: 7,
            producer_account_id: producer,
            height: 12,
            view: 3,
            round: 0,
            observer_account_id: observer,
        };
        let request = AsymptoteObserverObservationRequest {
            epoch: 7,
            assignment: assignment.clone(),
            block_hash: [61u8; 32],
            guardian_manifest_hash: [62u8; 32],
            guardian_decision_hash: [63u8; 32],
            guardian_counter: 64,
            guardian_trace_hash: [65u8; 32],
            guardian_measurement_root: [66u8; 32],
            guardian_checkpoint_root: [67u8; 32],
        };
        let evidence_hash = canonical_asymptote_observer_observation_request_hash(&request).unwrap();
        let challenge = AsymptoteObserverChallenge {
            challenge_id: [68u8; 32],
            epoch: 7,
            height: 12,
            view: 3,
            kind: AsymptoteObserverChallengeKind::TranscriptMismatch,
            challenger_account_id: observer,
            assignment: Some(assignment),
            observation_request: Some(request),
            transcript: None,
            canonical_close: None,
            evidence_hash,
            details: "observer rejected a malformed canonical observation request".into(),
        };

        let mut state = MockState::default();
        state
            .insert(
                VALIDATOR_SET_KEY,
                &write_validator_sets(&validator_sets(&[(21, 1), (22, 1), (23, 1)])).unwrap(),
            )
            .unwrap();

        with_ctx(|ctx| {
            run_async(registry.handle_service_call(
                &mut state,
                "report_asymptote_observer_challenge@v1",
                &codec::to_bytes_canonical(&challenge).unwrap(),
                ctx,
            ))
            .unwrap();
        });

        let quarantined: BTreeSet<AccountId> = codec::from_bytes_canonical(
            &state
                .get(QUARANTINED_VALIDATORS_KEY)
                .unwrap()
                .expect("quarantine set stored"),
        )
        .unwrap();
        assert!(quarantined.contains(&producer));
        assert!(!quarantined.contains(&observer));

        let stored_sets = read_validator_sets(
            &state
                .get(VALIDATOR_SET_KEY)
                .unwrap()
                .expect("validator sets stored"),
        )
        .unwrap();
        let next = stored_sets.next.expect("next validator set staged");
        assert!(!next.validators.iter().any(|validator| validator.account_id == producer));
        assert!(next.validators.iter().any(|validator| validator.account_id == observer));
    }

    #[test]
    fn invalid_canonical_close_challenge_blames_producer_and_remains_published_without_quarantine() {
        let registry = production_registry();
        let producer = AccountId([24u8; 32]);
        let observer = AccountId([25u8; 32]);
        let canonical_close = AsymptoteObserverCanonicalClose {
            epoch: 8,
            height: 13,
            view: 2,
            assignments_hash: [71u8; 32],
            transcripts_root: [72u8; 32],
            challenges_root: [73u8; 32],
            transcript_count: 1,
            challenge_count: 1,
            challenge_cutoff_timestamp_ms: 1_760_000_000,
        };
        let evidence_hash =
            canonical_asymptote_observer_canonical_close_hash(&canonical_close).unwrap();
        let challenge = AsymptoteObserverChallenge {
            challenge_id: [70u8; 32],
            epoch: 8,
            height: 13,
            view: 2,
            kind: AsymptoteObserverChallengeKind::InvalidCanonicalClose,
            challenger_account_id: producer,
            assignment: None,
            observation_request: None,
            transcript: None,
            canonical_close: Some(canonical_close),
            evidence_hash,
            details: "invalid proof-carried canonical close is challenge-dominated".into(),
        };
        let abort = AsymptoteObserverCanonicalAbort {
            epoch: 8,
            height: 13,
            view: 2,
            assignments_hash: [71u8; 32],
            transcripts_root: [72u8; 32],
            challenges_root: [73u8; 32],
            transcript_count: 1,
            challenge_count: 1,
            challenge_cutoff_timestamp_ms: 1_760_000_100,
        };

        let mut state = MockState::default();
        state
            .insert(
                VALIDATOR_SET_KEY,
                &write_validator_sets(&validator_sets(&[(24, 1), (25, 1)])).unwrap(),
            )
            .unwrap();

        with_ctx(|ctx| {
            run_async(registry.handle_service_call(
                &mut state,
                "report_asymptote_observer_challenge@v1",
                &codec::to_bytes_canonical(&challenge).unwrap(),
                ctx,
            ))
            .unwrap();
            run_async(registry.handle_service_call(
                &mut state,
                "publish_asymptote_observer_canonical_abort@v1",
                &codec::to_bytes_canonical(&abort).unwrap(),
                ctx,
            ))
            .unwrap();
        });

        assert!(state.get(QUARANTINED_VALIDATORS_KEY).unwrap().is_none());

        let stored_challenge = state
            .get(&guardian_registry_observer_challenge_key(8, 13, 2, &[70u8; 32]))
            .unwrap()
            .expect("observer challenge stored");
        let restored_challenge: AsymptoteObserverChallenge =
            codec::from_bytes_canonical(&stored_challenge).unwrap();
        assert_eq!(restored_challenge, challenge);

        let stored_abort = state
            .get(&guardian_registry_observer_canonical_abort_key(8, 13, 2))
            .unwrap()
            .expect("canonical abort stored");
        let restored_abort: AsymptoteObserverCanonicalAbort =
            codec::from_bytes_canonical(&stored_abort).unwrap();
        assert_eq!(restored_abort, abort);

        let evidence_registry: BTreeSet<[u8; 32]> = codec::from_bytes_canonical(
            &state
                .get(EVIDENCE_REGISTRY_KEY)
                .unwrap()
                .expect("evidence registry stored"),
        )
        .unwrap();
        assert_eq!(evidence_registry.len(), 1);

        let stored_sets = read_validator_sets(
            &state
                .get(VALIDATOR_SET_KEY)
                .unwrap()
                .expect("validator sets stored"),
        )
        .unwrap();
        let next = stored_sets.next.expect("next validator set staged");
        assert_eq!(next.validators.len(), 1);
        assert!(!next.validators.iter().any(|validator| validator.account_id == producer));
        assert!(next.validators.iter().any(|validator| validator.account_id == observer));
    }

    #[test]
    fn invalid_canonical_close_challenge_remains_published_when_membership_updates_are_disabled() {
        let registry = production_registry_without_accountable_membership_updates();
        let producer = AccountId([26u8; 32]);
        let observer = AccountId([27u8; 32]);
        let canonical_close = AsymptoteObserverCanonicalClose {
            epoch: 8,
            height: 14,
            view: 1,
            assignments_hash: [76u8; 32],
            transcripts_root: [77u8; 32],
            challenges_root: [78u8; 32],
            transcript_count: 1,
            challenge_count: 1,
            challenge_cutoff_timestamp_ms: 1_760_000_200,
        };
        let challenge = AsymptoteObserverChallenge {
            challenge_id: [75u8; 32],
            epoch: 8,
            height: 14,
            view: 1,
            kind: AsymptoteObserverChallengeKind::InvalidCanonicalClose,
            challenger_account_id: observer,
            assignment: None,
            observation_request: None,
            transcript: None,
            canonical_close: Some(canonical_close.clone()),
            evidence_hash: canonical_asymptote_observer_canonical_close_hash(&canonical_close)
                .unwrap(),
            details: "negative sealing object remains decisive without membership penalties".into(),
        };

        let mut state = MockState::default();
        state
            .insert(
                VALIDATOR_SET_KEY,
                &write_validator_sets(&validator_sets(&[(26, 1), (27, 1), (28, 1)])).unwrap(),
            )
            .unwrap();

        with_ctx(|ctx| {
            run_async(registry.handle_service_call(
                &mut state,
                "report_asymptote_observer_challenge@v1",
                &codec::to_bytes_canonical(&challenge).unwrap(),
                ctx,
            ))
            .unwrap();
        });

        let stored_challenge: AsymptoteObserverChallenge = codec::from_bytes_canonical(
            &state
                .get(&guardian_registry_observer_challenge_key(8, 14, 1, &[75u8; 32]))
                .unwrap()
                .expect("observer challenge stored"),
        )
        .unwrap();
        assert_eq!(stored_challenge, challenge);
        assert!(state.get(QUARANTINED_VALIDATORS_KEY).unwrap().is_none());

        let stored_sets = read_validator_sets(
            &state
                .get(VALIDATOR_SET_KEY)
                .unwrap()
                .expect("validator sets stored"),
        )
        .unwrap();
        assert!(stored_sets.next.is_none());
        assert!(stored_sets
            .current
            .validators
            .iter()
            .any(|validator| validator.account_id == producer));

        let evidence_registry: BTreeSet<[u8; 32]> = codec::from_bytes_canonical(
            &state
                .get(EVIDENCE_REGISTRY_KEY)
                .unwrap()
                .expect("evidence registry stored"),
        )
        .unwrap();
        assert_eq!(evidence_registry.len(), 1);
    }

    #[test]
    fn reporting_aft_omission_remains_published_when_membership_update_attempt_errors() {
        let registry = production_registry();
        let omission = OmissionProof {
            height: 16,
            offender_account_id: AccountId([41u8; 32]),
            tx_hash: [91u8; 32],
            bulletin_root: [92u8; 32],
            details: "ordering omission remains decisive even if penalty staging errors".into(),
        };

        let mut state = MockState::default();
        state.insert(VALIDATOR_SET_KEY, &[0xFF, 0x00, 0x01]).unwrap();

        with_ctx(|ctx| {
            run_async(registry.handle_service_call(
                &mut state,
                "report_aft_omission@v1",
                &codec::to_bytes_canonical(&omission).unwrap(),
                ctx,
            ))
            .unwrap();
        });

        let stored_omission: OmissionProof = codec::from_bytes_canonical(
            &state
                .get(&aft_omission_proof_key(omission.height, &omission.tx_hash))
                .unwrap()
                .expect("omission proof stored"),
        )
        .unwrap();
        assert_eq!(stored_omission, omission);

        let evidence_registry: BTreeSet<[u8; 32]> = codec::from_bytes_canonical(
            &state
                .get(EVIDENCE_REGISTRY_KEY)
                .unwrap()
                .expect("evidence registry stored"),
        )
        .unwrap();
        assert_eq!(evidence_registry.len(), 1);
    }

    #[test]
    fn reporting_observer_challenge_remains_published_when_membership_update_attempt_errors() {
        let registry = production_registry();
        let canonical_close = AsymptoteObserverCanonicalClose {
            epoch: 9,
            height: 17,
            view: 1,
            assignments_hash: [93u8; 32],
            transcripts_root: [94u8; 32],
            challenges_root: [95u8; 32],
            transcript_count: 1,
            challenge_count: 1,
            challenge_cutoff_timestamp_ms: 1_780_000_000,
        };
        let challenge = AsymptoteObserverChallenge {
            challenge_id: [96u8; 32],
            epoch: 9,
            height: 17,
            view: 1,
            kind: AsymptoteObserverChallengeKind::InvalidCanonicalClose,
            challenger_account_id: AccountId([42u8; 32]),
            assignment: None,
            observation_request: None,
            transcript: None,
            canonical_close: Some(canonical_close.clone()),
            evidence_hash: canonical_asymptote_observer_canonical_close_hash(&canonical_close)
                .unwrap(),
            details: "sealing abort remains decisive even if penalty staging errors".into(),
        };

        let mut state = MockState::default();
        state.insert(VALIDATOR_SET_KEY, &[0xFE, 0x00, 0x02]).unwrap();

        with_ctx(|ctx| {
            run_async(registry.handle_service_call(
                &mut state,
                "report_asymptote_observer_challenge@v1",
                &codec::to_bytes_canonical(&challenge).unwrap(),
                ctx,
            ))
            .unwrap();
        });

        let stored_challenge: AsymptoteObserverChallenge = codec::from_bytes_canonical(
            &state
                .get(&guardian_registry_observer_challenge_key(9, 17, 1, &[96u8; 32]))
                .unwrap()
                .expect("observer challenge stored"),
        )
        .unwrap();
        assert_eq!(stored_challenge, challenge);

        let evidence_registry: BTreeSet<[u8; 32]> = codec::from_bytes_canonical(
            &state
                .get(EVIDENCE_REGISTRY_KEY)
                .unwrap()
                .expect("evidence registry stored"),
        )
        .unwrap();
        assert_eq!(evidence_registry.len(), 1);
    }

    #[test]
    fn accountable_fault_skips_immediate_quarantine_when_current_liveness_would_break() {
        let registry = production_registry();
        let offender = AccountId([31u8; 32]);
        let omission = OmissionProof {
            height: 15,
            offender_account_id: offender,
            tx_hash: [71u8; 32],
            bulletin_root: [72u8; 32],
            details: "objective omission proof for a two-validator set".into(),
        };

        let mut state = MockState::default();
        state
            .insert(
                VALIDATOR_SET_KEY,
                &write_validator_sets(&validator_sets(&[(31, 1), (32, 1)])).unwrap(),
            )
            .unwrap();

        with_ctx(|ctx| {
            run_async(registry.handle_service_call(
                &mut state,
                "report_aft_omission@v1",
                &codec::to_bytes_canonical(&omission).unwrap(),
                ctx,
            ))
            .unwrap();
        });

        assert!(state.get(QUARANTINED_VALIDATORS_KEY).unwrap().is_none());

        let stored_sets = read_validator_sets(
            &state
                .get(VALIDATOR_SET_KEY)
                .unwrap()
                .expect("validator sets stored"),
        )
        .unwrap();
        let next = stored_sets.next.expect("next validator set staged");
        assert_eq!(next.validators.len(), 1);
        assert!(!next.validators.iter().any(|validator| validator.account_id == offender));
    }

    #[test]
    fn publishing_observer_canonical_sealing_artifacts_persists_registry_state() {
        let registry = production_registry();
        let transcript_commitment = AsymptoteObserverTranscriptCommitment {
            epoch: 7,
            height: 12,
            view: 3,
            assignments_hash: [1u8; 32],
            transcripts_root: [2u8; 32],
            transcript_count: 2,
        };
        let transcript = AsymptoteObserverTranscript {
            statement: AsymptoteObserverStatement {
                epoch: 7,
                assignment: AsymptoteObserverAssignment {
                    epoch: 7,
                    producer_account_id: AccountId([3u8; 32]),
                    height: 12,
                    view: 3,
                    round: 0,
                    observer_account_id: AccountId([4u8; 32]),
                },
                block_hash: [5u8; 32],
                guardian_manifest_hash: [6u8; 32],
                guardian_decision_hash: [7u8; 32],
                guardian_counter: 8,
                guardian_trace_hash: [9u8; 32],
                guardian_measurement_root: [10u8; 32],
                guardian_checkpoint_root: [11u8; 32],
                verdict: AsymptoteObserverVerdict::Ok,
                veto_kind: None,
                evidence_hash: [12u8; 32],
            },
            guardian_certificate: GuardianQuorumCertificate {
                manifest_hash: [13u8; 32],
                epoch: 7,
                decision_hash: [14u8; 32],
                ..Default::default()
            },
        };
        let challenge_commitment = AsymptoteObserverChallengeCommitment {
            epoch: 7,
            height: 12,
            view: 3,
            challenges_root: [15u8; 32],
            challenge_count: 1,
        };
        let evidence_hash = canonical_asymptote_observer_transcript_hash(&transcript).unwrap();
        let challenge = AsymptoteObserverChallenge {
            challenge_id: [16u8; 32],
            epoch: 7,
            height: 12,
            view: 3,
            kind: AsymptoteObserverChallengeKind::VetoTranscriptPresent,
            challenger_account_id: AccountId([17u8; 32]),
            assignment: Some(transcript.statement.assignment.clone()),
            observation_request: None,
            transcript: Some(transcript.clone()),
            canonical_close: None,
            evidence_hash,
            details: "published veto transcript dominates close".into(),
        };
        let abort = AsymptoteObserverCanonicalAbort {
            epoch: 7,
            height: 12,
            view: 3,
            assignments_hash: [19u8; 32],
            transcripts_root: [20u8; 32],
            challenges_root: [21u8; 32],
            transcript_count: 1,
            challenge_count: 1,
            challenge_cutoff_timestamp_ms: 1_750_000_100,
        };

        let mut state = MockState::default();
        with_ctx(|ctx| {
            run_async(registry.handle_service_call(
                &mut state,
                "publish_asymptote_observer_transcript_commitment@v1",
                &codec::to_bytes_canonical(&transcript_commitment).unwrap(),
                ctx,
            ))
            .unwrap();
            run_async(registry.handle_service_call(
                &mut state,
                "publish_asymptote_observer_transcript@v1",
                &codec::to_bytes_canonical(&transcript).unwrap(),
                ctx,
            ))
            .unwrap();
            run_async(registry.handle_service_call(
                &mut state,
                "publish_asymptote_observer_challenge_commitment@v1",
                &codec::to_bytes_canonical(&challenge_commitment).unwrap(),
                ctx,
            ))
            .unwrap();
            run_async(registry.handle_service_call(
                &mut state,
                "report_asymptote_observer_challenge@v1",
                &codec::to_bytes_canonical(&challenge).unwrap(),
                ctx,
            ))
            .unwrap();
            run_async(registry.handle_service_call(
                &mut state,
                "publish_asymptote_observer_canonical_abort@v1",
                &codec::to_bytes_canonical(&abort).unwrap(),
                ctx,
            ))
            .unwrap();
        });

        let stored_transcript_commitment = state
            .get(&guardian_registry_observer_transcript_commitment_key(7, 12, 3))
            .unwrap()
            .expect("transcript commitment stored");
        let restored_transcript_commitment: AsymptoteObserverTranscriptCommitment =
            codec::from_bytes_canonical(&stored_transcript_commitment).unwrap();
        assert_eq!(restored_transcript_commitment, transcript_commitment);

        let stored_transcript = state
            .get(&guardian_registry_observer_transcript_key(
                7,
                12,
                3,
                0,
                &AccountId([4u8; 32]),
            ))
            .unwrap()
            .expect("observer transcript stored");
        let restored_transcript: AsymptoteObserverTranscript =
            codec::from_bytes_canonical(&stored_transcript).unwrap();
        assert_eq!(restored_transcript, transcript);

        let stored_challenge_commitment = state
            .get(&guardian_registry_observer_challenge_commitment_key(7, 12, 3))
            .unwrap()
            .expect("challenge commitment stored");
        let restored_challenge_commitment: AsymptoteObserverChallengeCommitment =
            codec::from_bytes_canonical(&stored_challenge_commitment).unwrap();
        assert_eq!(restored_challenge_commitment, challenge_commitment);

        let stored_challenge = state
            .get(&guardian_registry_observer_challenge_key(7, 12, 3, &[16u8; 32]))
            .unwrap()
            .expect("observer challenge stored");
        let restored_challenge: AsymptoteObserverChallenge =
            codec::from_bytes_canonical(&stored_challenge).unwrap();
        assert_eq!(restored_challenge, challenge);

        let stored_abort = state
            .get(&guardian_registry_observer_canonical_abort_key(7, 12, 3))
            .unwrap()
            .expect("canonical abort stored");
        let restored_abort: AsymptoteObserverCanonicalAbort =
            codec::from_bytes_canonical(&stored_abort).unwrap();
        assert_eq!(restored_abort, abort);
    }

    #[test]
    fn observer_canonical_abort_dominates_close_but_close_cannot_override_abort() {
        let registry = production_registry();
        let close = AsymptoteObserverCanonicalClose {
            epoch: 9,
            height: 22,
            view: 1,
            assignments_hash: [81u8; 32],
            transcripts_root: [82u8; 32],
            challenges_root: [83u8; 32],
            transcript_count: 1,
            challenge_count: 0,
            challenge_cutoff_timestamp_ms: 1_770_000_000,
        };
        let abort = AsymptoteObserverCanonicalAbort {
            epoch: 9,
            height: 22,
            view: 1,
            assignments_hash: [81u8; 32],
            transcripts_root: [82u8; 32],
            challenges_root: [84u8; 32],
            transcript_count: 1,
            challenge_count: 1,
            challenge_cutoff_timestamp_ms: 1_770_000_100,
        };

        let mut close_first_state = MockState::default();
        with_ctx(|ctx| {
            run_async(registry.handle_service_call(
                &mut close_first_state,
                "publish_asymptote_observer_canonical_close@v1",
                &codec::to_bytes_canonical(&close).unwrap(),
                ctx,
            ))
            .unwrap();
            run_async(registry.handle_service_call(
                &mut close_first_state,
                "publish_asymptote_observer_canonical_abort@v1",
                &codec::to_bytes_canonical(&abort).unwrap(),
                ctx,
            ))
            .unwrap();
        });
        assert!(close_first_state
            .get(&guardian_registry_observer_canonical_close_key(9, 22, 1))
            .unwrap()
            .is_none());
        let stored_abort: AsymptoteObserverCanonicalAbort = codec::from_bytes_canonical(
            &close_first_state
                .get(&guardian_registry_observer_canonical_abort_key(9, 22, 1))
                .unwrap()
                .expect("abort stored"),
        )
        .unwrap();
        assert_eq!(stored_abort, abort);

        let mut abort_first_state = MockState::default();
        with_ctx(|ctx| {
            run_async(registry.handle_service_call(
                &mut abort_first_state,
                "publish_asymptote_observer_canonical_abort@v1",
                &codec::to_bytes_canonical(&abort).unwrap(),
                ctx,
            ))
            .unwrap();
            let err = run_async(registry.handle_service_call(
                &mut abort_first_state,
                "publish_asymptote_observer_canonical_close@v1",
                &codec::to_bytes_canonical(&close).unwrap(),
                ctx,
            ))
            .unwrap_err();
            assert!(err.to_string().contains("canonical abort is already persisted"));
        });
    }

    #[test]
    fn reporting_observer_challenge_materializes_challenge_commitment_and_abort_from_close() {
        let registry = production_registry();
        let close = AsymptoteObserverCanonicalClose {
            epoch: 11,
            height: 24,
            view: 2,
            assignments_hash: [101u8; 32],
            transcripts_root: [102u8; 32],
            challenges_root: [0u8; 32],
            transcript_count: 1,
            challenge_count: 0,
            challenge_cutoff_timestamp_ms: 1_780_000_500,
        };
        let challenge = AsymptoteObserverChallenge {
            challenge_id: [103u8; 32],
            epoch: 11,
            height: 24,
            view: 2,
            kind: AsymptoteObserverChallengeKind::InvalidCanonicalClose,
            challenger_account_id: AccountId([104u8; 32]),
            assignment: None,
            observation_request: None,
            transcript: None,
            canonical_close: Some(close.clone()),
            evidence_hash: canonical_asymptote_observer_canonical_close_hash(&close).unwrap(),
            details: "late challenge dominates previously published close".into(),
        };

        let mut state = MockState::default();
        with_ctx(|ctx| {
            run_async(registry.handle_service_call(
                &mut state,
                "publish_asymptote_observer_canonical_close@v1",
                &codec::to_bytes_canonical(&close).unwrap(),
                ctx,
            ))
            .unwrap();
            run_async(registry.handle_service_call(
                &mut state,
                "report_asymptote_observer_challenge@v1",
                &codec::to_bytes_canonical(&challenge).unwrap(),
                ctx,
            ))
            .unwrap();
        });

        assert!(state
            .get(&guardian_registry_observer_canonical_close_key(11, 24, 2))
            .unwrap()
            .is_none());
        let stored_commitment: AsymptoteObserverChallengeCommitment = codec::from_bytes_canonical(
            &state
                .get(&guardian_registry_observer_challenge_commitment_key(11, 24, 2))
                .unwrap()
                .expect("challenge commitment stored"),
        )
        .unwrap();
        assert_eq!(stored_commitment.challenge_count, 1);
        let stored_abort: AsymptoteObserverCanonicalAbort = codec::from_bytes_canonical(
            &state
                .get(&guardian_registry_observer_canonical_abort_key(11, 24, 2))
                .unwrap()
                .expect("abort stored"),
        )
        .unwrap();
        assert_eq!(stored_abort.assignments_hash, close.assignments_hash);
        assert_eq!(stored_abort.transcripts_root, close.transcripts_root);
        assert_eq!(stored_abort.challenges_root, stored_commitment.challenges_root);
        assert_eq!(stored_abort.challenge_count, 1);
        assert_eq!(
            stored_abort.challenge_cutoff_timestamp_ms,
            close.challenge_cutoff_timestamp_ms
        );
    }

    #[test]
    fn canonical_observer_policy_requires_non_zero_challenge_window() {
        let registry = production_registry();
        let policy = AsymptotePolicy {
            epoch: 3,
            observer_rounds: 1,
            observer_committee_size: 1,
            observer_sealing_mode: AsymptoteObserverSealingMode::CanonicalChallengeV1,
            ..Default::default()
        };

        let mut state = MockState::default();
        let mut err = None;
        with_ctx(|ctx| {
            err = Some(
                run_async(registry.handle_service_call(
                    &mut state,
                    "publish_asymptote_policy@v1",
                    &codec::to_bytes_canonical(&policy).unwrap(),
                    ctx,
                ))
                .unwrap_err(),
            );
        });
        let err = err.expect("policy publication should fail");

        assert!(err
            .to_string()
            .contains("canonical observer sealing mode requires a non-zero challenge window"));
    }
}
