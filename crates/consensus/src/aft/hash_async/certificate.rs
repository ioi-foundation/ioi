use crate::aft::authenticated_quorum::{
    pq_optimistic_quorum_geometry, ValidatorKeyRegistry, VerifiedSigner,
};
use ioi_types::app::{
    canonical_validator_set_hash, AftAsyncDecisionVoteV1, AftAsyncExecutedBlockCertificateV1,
    AftAsyncExecutedBlockDecisionV1, AftAsyncExecutedBlockVoteV1, AftAsyncInstanceV1,
    AftAsyncOrderingCertificateV1, AftAsyncOrderingDecisionV1, AftAsyncParentProofV1,
    AftAsyncProposalAvailabilityCertificateV1, AftAsyncProposalAvailabilityVoteV1,
    AftAsyncProposalDescriptorV1, AftAsyncSelectedBatchWitnessV1, AftAsyncTranscriptSummaryV1,
    SignatureSuite, ValidatorSetV1, AFT_ASYNC_PROTOCOL_VERSION_V1, AFT_ASYNC_SCHEMA_VERSION_V1,
};
use ioi_types::error::ConsensusError;
use std::collections::BTreeMap;

/// A portable asynchronous ordering certificate whose exact-q ML-DSA votes
/// were rebound to the rooted effective validator set and raw-key registry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedAsyncOrderingCertificateV1 {
    /// Certificate that was verified.
    pub certificate: AftAsyncOrderingCertificateV1,
    /// Cryptographically verified signers in member-index order.
    pub signers: Vec<VerifiedSigner>,
}

/// A proposal availability certificate whose exact-q holder votes were
/// verified against the rooted effective validator set and raw-key registry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedAsyncProposalAvailabilityCertificateV1 {
    /// Certificate that was verified.
    pub certificate: AftAsyncProposalAvailabilityCertificateV1,
    /// Cryptographically verified holders in member-index order.
    pub holders: Vec<VerifiedSigner>,
}

/// Executed-block evidence whose ordering, availability, and exact-q block
/// votes were all rebound to one rooted effective validator set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedAsyncExecutedBlockCertificateV1 {
    /// Certificate that was verified.
    pub certificate: AftAsyncExecutedBlockCertificateV1,
    /// Cryptographically verified executed-block signers.
    pub signers: Vec<VerifiedSigner>,
}

/// Typed asynchronous predecessor proof rebound to canonical membership and
/// raw PQ keys. This is distinct from—and cannot be exported as—a native QC.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedAsyncParentProofV1 {
    /// Proof that was verified.
    pub proof: AftAsyncParentProofV1,
    /// Cryptographically verified executed-block signers.
    pub signers: Vec<VerifiedSigner>,
}

/// Verifies the complete typed predecessor bridge. Shape validation binds the
/// exact parent header, ordering and payload witness; this layer additionally
/// checks rooted membership, every certificate signature, and the virtual
/// producer identity derived from the first canonical member.
pub fn verify_async_parent_proof(
    proof: &AftAsyncParentProofV1,
    set: &ValidatorSetV1,
    registry: &ValidatorKeyRegistry,
) -> Result<VerifiedAsyncParentProofV1, ConsensusError> {
    proof
        .validate_shape()
        .map_err(ConsensusError::BlockVerificationFailed)?;
    let verified = verify_async_executed_block_certificate(
        &proof.executed_certificate,
        &proof.batch_witness,
        set,
        registry,
    )?;
    let header = proof
        .parent_header()
        .map_err(ConsensusError::BlockVerificationFailed)?;
    let instance = &proof.executed_certificate.decision.instance;
    let first = set.validators.first().ok_or_else(|| {
        ConsensusError::BlockVerificationFailed(
            "AFT asynchronous parent proof has empty membership".into(),
        )
    })?;
    let key = registry
        .get(&first.consensus_key.public_key_hash)
        .ok_or_else(|| {
            ConsensusError::BlockVerificationFailed(
                "AFT asynchronous parent proof lacks its virtual producer key".into(),
            )
        })?;
    let terminal_view = instance
        .fallback_start
        .trigger_certificate
        .consecutive_timeout_certificates
        .last()
        .map(|timeout| timeout.view.saturating_add(1))
        .ok_or_else(|| {
            ConsensusError::BlockVerificationFailed(
                "AFT asynchronous parent proof lacks a terminal timeout view".into(),
            )
        })?;
    let expected_members = set
        .validators
        .iter()
        .map(|member| member.account_id.0.to_vec())
        .collect::<Vec<_>>();
    if header.view != terminal_view
        || header.validator_set != expected_members
        || header.producer_account_id != first.account_id
        || header.producer_key_suite != first.consensus_key.suite
        || header.producer_pubkey_hash != first.consensus_key.public_key_hash
        || header.producer_pubkey != key.raw()
    {
        return Err(ConsensusError::BlockVerificationFailed(
            "AFT asynchronous parent proof is not bound to its rooted virtual producer".into(),
        ));
    }
    Ok(VerifiedAsyncParentProofV1 {
        proof: proof.clone(),
        signers: verified.signers,
    })
}

/// Verifies the complete ordering -> payload -> executed-block chain.
pub fn verify_async_executed_block_certificate(
    certificate: &AftAsyncExecutedBlockCertificateV1,
    witness: &AftAsyncSelectedBatchWitnessV1,
    set: &ValidatorSetV1,
    registry: &ValidatorKeyRegistry,
) -> Result<VerifiedAsyncExecutedBlockCertificateV1, ConsensusError> {
    certificate
        .validate_with_witness(witness)
        .map_err(ConsensusError::BlockVerificationFailed)?;
    let instance = &certificate.decision.instance;
    validate_instance_membership(instance, set)?;
    verify_async_ordering_certificate(&certificate.ordering, set, registry)?;
    for selected in &witness.selected {
        verify_async_proposal_availability_certificate(
            &selected.availability_certificate,
            instance,
            set,
            registry,
        )?;
    }
    let signers = certificate
        .votes
        .iter()
        .map(|vote| verify_executed_vote(vote, &certificate.decision, set, registry))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(VerifiedAsyncExecutedBlockCertificateV1 {
        certificate: certificate.clone(),
        signers,
    })
}

/// Verifies validate-and-hold evidence and its complete instance/membership
/// binding before a proposal reference is admitted to ACS.
pub fn verify_async_proposal_availability_certificate(
    certificate: &AftAsyncProposalAvailabilityCertificateV1,
    instance: &AftAsyncInstanceV1,
    set: &ValidatorSetV1,
    registry: &ValidatorKeyRegistry,
) -> Result<VerifiedAsyncProposalAvailabilityCertificateV1, ConsensusError> {
    certificate
        .validate_shape(instance)
        .map_err(ConsensusError::BlockVerificationFailed)?;
    validate_instance_membership(instance, set)?;
    let holders = certificate
        .votes
        .iter()
        .map(|vote| {
            verify_availability_vote(vote, &certificate.descriptor, instance, set, registry)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(VerifiedAsyncProposalAvailabilityCertificateV1 {
        certificate: certificate.clone(),
        holders,
    })
}

/// Exact-proposal validate-and-hold vote collector. It cannot combine holders
/// across descriptors, instances, configurations, or member indices.
#[derive(Clone, Debug)]
pub struct AsyncProposalAvailabilityVotePool {
    instance: AftAsyncInstanceV1,
    descriptor: AftAsyncProposalDescriptorV1,
    votes: BTreeMap<u16, AftAsyncProposalAvailabilityVoteV1>,
    formed: Option<AftAsyncProposalAvailabilityCertificateV1>,
}

impl AsyncProposalAvailabilityVotePool {
    /// Creates a pool for one fully instance-bound proposal descriptor.
    pub fn new(
        instance: AftAsyncInstanceV1,
        descriptor: AftAsyncProposalDescriptorV1,
    ) -> Result<Self, ConsensusError> {
        descriptor
            .validate_for(&instance)
            .map_err(ConsensusError::BlockVerificationFailed)?;
        Ok(Self {
            instance,
            descriptor,
            votes: BTreeMap::new(),
            formed: None,
        })
    }

    /// Verifies and inserts one rooted holder vote. Exact redelivery is
    /// idempotent; any attempt to rebind an index is rejected.
    pub fn insert(
        &mut self,
        vote: AftAsyncProposalAvailabilityVoteV1,
        set: &ValidatorSetV1,
        registry: &ValidatorKeyRegistry,
    ) -> Result<Option<AftAsyncProposalAvailabilityCertificateV1>, ConsensusError> {
        validate_instance_membership(&self.instance, set)?;
        verify_availability_vote(&vote, &self.descriptor, &self.instance, set, registry)?;
        match self.votes.get(&vote.member_index) {
            // ML-DSA implementations may produce different valid encodings
            // for the same signed statement. The rooted key, index and
            // statement were already verified, so preserve the first byte
            // representation and treat redelivery as logically idempotent.
            Some(_) => return Ok(self.certificate_if_ready()),
            None => {
                if self.formed.is_some() {
                    return Ok(self.certificate_if_ready());
                }
                self.votes.insert(vote.member_index, vote);
            }
        }
        if self.votes.len() == self.instance.geometry.quorum as usize {
            self.formed = Some(AftAsyncProposalAvailabilityCertificateV1 {
                protocol_version: AFT_ASYNC_PROTOCOL_VERSION_V1,
                schema_version: AFT_ASYNC_SCHEMA_VERSION_V1,
                descriptor: self.descriptor.clone(),
                votes: self.votes.values().cloned().collect(),
            });
        }
        Ok(self.certificate_if_ready())
    }

    fn certificate_if_ready(&self) -> Option<AftAsyncProposalAvailabilityCertificateV1> {
        self.formed.clone()
    }
}

/// Verifies the complete asynchronous certificate against rooted membership.
pub fn verify_async_ordering_certificate(
    certificate: &AftAsyncOrderingCertificateV1,
    set: &ValidatorSetV1,
    registry: &ValidatorKeyRegistry,
) -> Result<VerifiedAsyncOrderingCertificateV1, ConsensusError> {
    certificate
        .validate_shape()
        .map_err(ConsensusError::BlockVerificationFailed)?;
    validate_membership_binding(&certificate.decision, set)?;
    let signers = certificate
        .votes
        .iter()
        .map(|vote| verify_vote(vote, &certificate.decision, set, registry))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(VerifiedAsyncOrderingCertificateV1 {
        certificate: certificate.clone(),
        signers,
    })
}

/// Exact-decision vote collector. It never combines votes across decisions,
/// instances, configurations, or member indices.
#[derive(Clone, Debug)]
pub struct AsyncOrderingVotePool {
    decision: AftAsyncOrderingDecisionV1,
    transcript: AftAsyncTranscriptSummaryV1,
    votes: BTreeMap<u16, AftAsyncDecisionVoteV1>,
    formed: Option<AftAsyncOrderingCertificateV1>,
}

impl AsyncOrderingVotePool {
    /// Creates a pool only when the transcript recomputes the decision's root.
    pub fn new(
        decision: AftAsyncOrderingDecisionV1,
        transcript: AftAsyncTranscriptSummaryV1,
    ) -> Result<Self, ConsensusError> {
        decision
            .validate()
            .map_err(ConsensusError::BlockVerificationFailed)?;
        transcript
            .validate(&decision.instance)
            .map_err(ConsensusError::BlockVerificationFailed)?;
        if transcript
            .transcript_root(&decision.instance)
            .map_err(ConsensusError::BlockVerificationFailed)?
            != decision.transcript_root
        {
            return Err(ConsensusError::BlockVerificationFailed(
                "asynchronous vote pool transcript does not bind the decision".into(),
            ));
        }
        Ok(Self {
            decision,
            transcript,
            votes: BTreeMap::new(),
            formed: None,
        })
    }

    /// Verifies and inserts one rooted vote. Returns the exact-q certificate
    /// once formed; exact duplicate delivery is idempotent.
    pub fn insert(
        &mut self,
        vote: AftAsyncDecisionVoteV1,
        set: &ValidatorSetV1,
        registry: &ValidatorKeyRegistry,
    ) -> Result<Option<AftAsyncOrderingCertificateV1>, ConsensusError> {
        validate_membership_binding(&self.decision, set)?;
        verify_vote(&vote, &self.decision, set, registry)?;
        match self.votes.get(&vote.member_index) {
            Some(_) => return Ok(self.certificate_if_ready()),
            None => {
                if self.formed.is_some() {
                    return Ok(self.certificate_if_ready());
                }
                self.votes.insert(vote.member_index, vote);
            }
        }
        if self.votes.len() == self.decision.instance.geometry.quorum as usize {
            self.formed = Some(AftAsyncOrderingCertificateV1 {
                protocol_version: AFT_ASYNC_PROTOCOL_VERSION_V1,
                schema_version: AFT_ASYNC_SCHEMA_VERSION_V1,
                decision: self.decision.clone(),
                transcript: self.transcript.clone(),
                votes: self.votes.values().cloned().collect(),
            });
        }
        Ok(self.certificate_if_ready())
    }

    fn certificate_if_ready(&self) -> Option<AftAsyncOrderingCertificateV1> {
        self.formed.clone()
    }
}

/// Exact-decision collector for the post-execution block binding. It cannot
/// combine votes across ordering evidence, witnesses, or block hashes.
#[derive(Clone, Debug)]
pub struct AsyncExecutedBlockVotePool {
    decision: AftAsyncExecutedBlockDecisionV1,
    ordering: AftAsyncOrderingCertificateV1,
    votes: BTreeMap<u16, AftAsyncExecutedBlockVoteV1>,
    formed: Option<AftAsyncExecutedBlockCertificateV1>,
}

impl AsyncExecutedBlockVotePool {
    /// Opens one pool after complete structural witness validation.
    pub fn new(
        decision: AftAsyncExecutedBlockDecisionV1,
        ordering: AftAsyncOrderingCertificateV1,
    ) -> Result<Self, ConsensusError> {
        decision
            .validate_shape()
            .map_err(ConsensusError::BlockVerificationFailed)?;
        ordering
            .validate_shape()
            .map_err(ConsensusError::BlockVerificationFailed)?;
        if !ordering
            .decision
            .instance
            .consensus_equivalent(&decision.instance)
            .map_err(ConsensusError::BlockVerificationFailed)?
            || ordering
                .decision
                .decision_hash()
                .map_err(ConsensusError::BlockVerificationFailed)?
                != decision.ordering_decision_hash
        {
            return Err(ConsensusError::BlockVerificationFailed(
                "executed-block pool ordering certificate is rebound".into(),
            ));
        }
        Ok(Self {
            decision,
            ordering,
            votes: BTreeMap::new(),
            formed: None,
        })
    }

    /// Verifies one rooted vote and emits the exact-q certificate once.
    pub fn insert(
        &mut self,
        vote: AftAsyncExecutedBlockVoteV1,
        set: &ValidatorSetV1,
        registry: &ValidatorKeyRegistry,
    ) -> Result<Option<AftAsyncExecutedBlockCertificateV1>, ConsensusError> {
        let instance = &self.decision.instance;
        validate_instance_membership(instance, set)?;
        verify_executed_vote(&vote, &self.decision, set, registry)?;
        match self.votes.get(&vote.member_index) {
            Some(_) => return Ok(self.formed.clone()),
            None => {
                if self.formed.is_some() {
                    return Ok(self.formed.clone());
                }
                self.votes.insert(vote.member_index, vote);
            }
        }
        if self.votes.len() == instance.geometry.quorum as usize {
            self.formed = Some(AftAsyncExecutedBlockCertificateV1 {
                protocol_version: AFT_ASYNC_PROTOCOL_VERSION_V1,
                schema_version: AFT_ASYNC_SCHEMA_VERSION_V1,
                decision: self.decision.clone(),
                ordering: self.ordering.clone(),
                votes: self.votes.values().cloned().collect(),
            });
        }
        Ok(self.formed.clone())
    }
}

fn validate_membership_binding(
    decision: &AftAsyncOrderingDecisionV1,
    set: &ValidatorSetV1,
) -> Result<(), ConsensusError> {
    validate_instance_membership(&decision.instance, set)
}

fn validate_instance_membership(
    instance: &AftAsyncInstanceV1,
    set: &ValidatorSetV1,
) -> Result<(), ConsensusError> {
    let geometry = pq_optimistic_quorum_geometry(set)?;
    if usize::try_from(geometry.n).ok() != Some(set.validators.len())
        || u32::from(instance.geometry.n) != geometry.n
        || u32::from(instance.geometry.f) != geometry.f
        || u32::from(instance.geometry.quorum) != geometry.q
    {
        return Err(ConsensusError::BlockVerificationFailed(
            "asynchronous certificate geometry does not match rooted membership".into(),
        ));
    }
    let set_hash =
        canonical_validator_set_hash(set).map_err(ConsensusError::BlockVerificationFailed)?;
    if instance.scope.configuration_hash != set_hash
        || instance.scope.epoch != set.effective_from_height
        || instance.height < set.effective_from_height
    {
        return Err(ConsensusError::BlockVerificationFailed(
            "asynchronous certificate scope does not match rooted membership".into(),
        ));
    }
    Ok(())
}

fn verify_availability_vote(
    vote: &AftAsyncProposalAvailabilityVoteV1,
    descriptor: &AftAsyncProposalDescriptorV1,
    instance: &AftAsyncInstanceV1,
    set: &ValidatorSetV1,
    registry: &ValidatorKeyRegistry,
) -> Result<VerifiedSigner, ConsensusError> {
    vote.validate_for(descriptor, instance)
        .map_err(ConsensusError::BlockVerificationFailed)?;
    let member = set
        .validators
        .get(vote.member_index as usize)
        .ok_or_else(|| {
            ConsensusError::BlockVerificationFailed(
                "asynchronous availability vote member index is out of range".into(),
            )
        })?;
    if member.account_id != vote.voter
        || member.weight != 1
        || member.consensus_key.suite != SignatureSuite::ML_DSA_44
        || instance.height < member.consensus_key.since_height
    {
        return Err(ConsensusError::BlockVerificationFailed(
            "asynchronous availability vote does not match its rooted member record".into(),
        ));
    }
    let key = registry
        .get(&member.consensus_key.public_key_hash)
        .ok_or_else(|| {
            ConsensusError::BlockVerificationFailed(
                "asynchronous availability vote lacks its rooted raw public key".into(),
            )
        })?;
    if key.suite() != SignatureSuite::ML_DSA_44
        || key.key_hash()? != member.consensus_key.public_key_hash
    {
        return Err(ConsensusError::BlockVerificationFailed(
            "asynchronous availability verifier key does not match membership".into(),
        ));
    }
    let preimage = AftAsyncProposalAvailabilityVoteV1::signing_bytes(
        descriptor,
        vote.member_index,
        vote.voter,
    )
    .map_err(ConsensusError::BlockVerificationFailed)?;
    if !key.verify(&preimage, &vote.signature) {
        return Err(ConsensusError::BlockVerificationFailed(
            "asynchronous availability vote signature is invalid".into(),
        ));
    }
    Ok(VerifiedSigner {
        account_id: vote.voter,
        suite: SignatureSuite::ML_DSA_44,
        public_key: key.raw().to_vec(),
        signature: vote.signature.clone(),
    })
}

fn verify_vote(
    vote: &AftAsyncDecisionVoteV1,
    decision: &AftAsyncOrderingDecisionV1,
    set: &ValidatorSetV1,
    registry: &ValidatorKeyRegistry,
) -> Result<VerifiedSigner, ConsensusError> {
    vote.validate_for(decision)
        .map_err(ConsensusError::BlockVerificationFailed)?;
    if vote.signature_suite != SignatureSuite::ML_DSA_44 {
        return Err(ConsensusError::BlockVerificationFailed(
            "asynchronous ordering vote is not ML-DSA-44".into(),
        ));
    }
    let member = set
        .validators
        .get(vote.member_index as usize)
        .ok_or_else(|| {
            ConsensusError::BlockVerificationFailed(
                "asynchronous ordering vote member index is out of range".into(),
            )
        })?;
    if member.account_id != vote.voter
        || member.weight != 1
        || member.consensus_key.suite != SignatureSuite::ML_DSA_44
        || decision.instance.height < member.consensus_key.since_height
    {
        return Err(ConsensusError::BlockVerificationFailed(
            "asynchronous ordering vote does not match its rooted member record".into(),
        ));
    }
    let key = registry
        .get(&member.consensus_key.public_key_hash)
        .ok_or_else(|| {
            ConsensusError::BlockVerificationFailed(
                "asynchronous ordering vote lacks its rooted raw public key".into(),
            )
        })?;
    if key.suite() != SignatureSuite::ML_DSA_44
        || key.key_hash()? != member.consensus_key.public_key_hash
    {
        return Err(ConsensusError::BlockVerificationFailed(
            "asynchronous ordering verifier key does not match membership".into(),
        ));
    }
    let preimage = AftAsyncDecisionVoteV1::signing_bytes(decision, vote.member_index, vote.voter)
        .map_err(ConsensusError::BlockVerificationFailed)?;
    if !key.verify(&preimage, &vote.signature) {
        return Err(ConsensusError::BlockVerificationFailed(
            "asynchronous ordering vote signature is invalid".into(),
        ));
    }
    Ok(VerifiedSigner {
        account_id: vote.voter,
        suite: SignatureSuite::ML_DSA_44,
        public_key: key.raw().to_vec(),
        signature: vote.signature.clone(),
    })
}

fn verify_executed_vote(
    vote: &AftAsyncExecutedBlockVoteV1,
    decision: &AftAsyncExecutedBlockDecisionV1,
    set: &ValidatorSetV1,
    registry: &ValidatorKeyRegistry,
) -> Result<VerifiedSigner, ConsensusError> {
    vote.validate_for(decision)
        .map_err(ConsensusError::BlockVerificationFailed)?;
    let instance = &decision.instance;
    let member = set
        .validators
        .get(vote.member_index as usize)
        .ok_or_else(|| {
            ConsensusError::BlockVerificationFailed(
                "asynchronous executed-block vote member index is out of range".into(),
            )
        })?;
    if member.account_id != vote.voter
        || member.weight != 1
        || member.consensus_key.suite != SignatureSuite::ML_DSA_44
        || instance.height < member.consensus_key.since_height
    {
        return Err(ConsensusError::BlockVerificationFailed(
            "asynchronous executed-block vote does not match rooted membership".into(),
        ));
    }
    let key = registry
        .get(&member.consensus_key.public_key_hash)
        .ok_or_else(|| {
            ConsensusError::BlockVerificationFailed(
                "asynchronous executed-block vote lacks its rooted raw public key".into(),
            )
        })?;
    if key.suite() != SignatureSuite::ML_DSA_44
        || key.key_hash()? != member.consensus_key.public_key_hash
    {
        return Err(ConsensusError::BlockVerificationFailed(
            "asynchronous executed-block verifier key does not match membership".into(),
        ));
    }
    let preimage =
        AftAsyncExecutedBlockVoteV1::signing_bytes(decision, vote.member_index, vote.voter)
            .map_err(ConsensusError::BlockVerificationFailed)?;
    if !key.verify(&preimage, &vote.signature) {
        return Err(ConsensusError::BlockVerificationFailed(
            "asynchronous executed-block vote signature is invalid".into(),
        ));
    }
    Ok(VerifiedSigner {
        account_id: vote.voter,
        suite: SignatureSuite::ML_DSA_44,
        public_key: key.raw().to_vec(),
        signature: vote.signature.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aft::hash_async::node::tests_support::{proposal_for, test_instance};
    use crate::aft::hash_async::HashAsyncOrderingAdapter;
    use ioi_api::crypto::{SerializableKey, SigningKeyPair};
    use ioi_crypto::security::SecurityLevel;
    use ioi_crypto::sign::dilithium::{MldsaKeyPair, MldsaScheme};
    use ioi_types::app::{account_id_from_key_material, AccountId, ActiveKeyRecord, ValidatorV1};

    fn fixture() -> (
        AftAsyncOrderingDecisionV1,
        AftAsyncTranscriptSummaryV1,
        ValidatorSetV1,
        ValidatorKeyRegistry,
        Vec<MldsaKeyPair>,
    ) {
        let mut keyed = (0..4)
            .map(|_| {
                let keypair = MldsaScheme::new(SecurityLevel::Level2)
                    .generate_keypair()
                    .unwrap();
                let raw = keypair.public_key().to_bytes();
                let account = AccountId(
                    account_id_from_key_material(SignatureSuite::ML_DSA_44, &raw).unwrap(),
                );
                (account, keypair, raw)
            })
            .collect::<Vec<_>>();
        keyed.sort_by_key(|(account, _, _)| *account);
        let validators = keyed
            .iter()
            .map(|(account, _, raw)| ValidatorV1 {
                account_id: *account,
                weight: 1,
                consensus_key: ActiveKeyRecord {
                    suite: SignatureSuite::ML_DSA_44,
                    public_key_hash: account_id_from_key_material(SignatureSuite::ML_DSA_44, raw)
                        .unwrap(),
                    since_height: 1,
                },
            })
            .collect::<Vec<_>>();
        let set = ValidatorSetV1 {
            effective_from_height: 1,
            total_weight: 4,
            validators,
        };
        let mut instance = test_instance();
        let configuration_hash = canonical_validator_set_hash(&set).unwrap();
        instance.scope.configuration_hash = configuration_hash;
        instance.fallback_start.scope.configuration_hash = configuration_hash;
        instance
            .fallback_start
            .trigger_certificate
            .consecutive_timeout_certificates
            .iter_mut()
            .for_each(|certificate| {
                certificate.scope.configuration_hash = configuration_hash;
                certificate.votes.iter_mut().for_each(|vote| {
                    vote.scope.configuration_hash = configuration_hash;
                });
            });
        instance.fallback_instance_id =
            ioi_types::app::FallbackStartCertificateV1::derive_instance_id(
                instance.scope,
                instance.height,
            )
            .unwrap();
        instance.fallback_start.fallback_instance_id = instance.fallback_instance_id;
        instance.fallback_start_hash = instance.fallback_start.certificate_hash().unwrap();
        instance.validate().unwrap();
        let selected = (0..3)
            .map(|index| proposal_for(&instance, index))
            .collect::<Vec<_>>();
        let (decision, transcript) = HashAsyncOrderingAdapter::decide(
            instance,
            0,
            &[0, 1, 2],
            &selected.iter().cloned().map(|p| (p.proposer, p)).collect(),
        )
        .unwrap();
        let mut registry = ValidatorKeyRegistry::new();
        for (_, _, raw) in &keyed {
            registry
                .learn_raw_public_key(SignatureSuite::ML_DSA_44, raw)
                .unwrap();
        }
        let keypairs = keyed.into_iter().map(|(_, keypair, _)| keypair).collect();
        (decision, transcript, set, registry, keypairs)
    }

    #[test]
    fn exact_q_rooted_mldsa_votes_form_and_verify_certificate() {
        let (decision, transcript, set, registry, keypairs) = fixture();
        let mut pool = AsyncOrderingVotePool::new(decision.clone(), transcript).unwrap();
        let mut certificate = None;
        for (index, keypair) in keypairs.iter().take(3).enumerate() {
            let member_index = index as u16;
            let voter = set.validators[index].account_id;
            let preimage =
                AftAsyncDecisionVoteV1::signing_bytes(&decision, member_index, voter).unwrap();
            let vote = AftAsyncDecisionVoteV1 {
                decision_hash: decision.decision_hash().unwrap(),
                member_index,
                voter,
                signature_suite: SignatureSuite::ML_DSA_44,
                signature: keypair.sign(&preimage).unwrap().to_bytes(),
            };
            certificate = pool.insert(vote, &set, &registry).unwrap();
        }
        let certificate = certificate.unwrap();
        let verified = verify_async_ordering_certificate(&certificate, &set, &registry).unwrap();
        assert_eq!(verified.signers.len(), 3);
    }

    #[test]
    fn certificate_refuses_member_rebinding_and_signature_mutation() {
        let (decision, transcript, set, registry, keypairs) = fixture();
        let voter = set.validators[0].account_id;
        let preimage = AftAsyncDecisionVoteV1::signing_bytes(&decision, 0, voter).unwrap();
        let mut vote = AftAsyncDecisionVoteV1 {
            decision_hash: decision.decision_hash().unwrap(),
            member_index: 0,
            voter,
            signature_suite: SignatureSuite::ML_DSA_44,
            signature: keypairs[0].sign(&preimage).unwrap().to_bytes(),
        };
        let mut pool = AsyncOrderingVotePool::new(decision, transcript).unwrap();
        vote.signature[0] ^= 1;
        assert!(pool.insert(vote, &set, &registry).is_err());
    }

    #[test]
    fn exact_q_rooted_holders_authorize_one_proposal_reference() {
        let (decision, _, set, registry, keypairs) = fixture();
        let instance = decision.instance;
        let descriptor = AftAsyncProposalDescriptorV1 {
            instance_hash: instance.instance_hash().unwrap(),
            proposer: 0,
            proposal_hash: [0x51; 32],
            payload_len: 4096,
            parent_root: instance.locked_root,
        };
        let mut pool =
            AsyncProposalAvailabilityVotePool::new(instance.clone(), descriptor.clone()).unwrap();
        let mut certificate = None;
        for (index, keypair) in keypairs.iter().take(3).enumerate() {
            let member_index = index as u16;
            let voter = set.validators[index].account_id;
            let preimage =
                AftAsyncProposalAvailabilityVoteV1::signing_bytes(&descriptor, member_index, voter)
                    .unwrap();
            let vote = AftAsyncProposalAvailabilityVoteV1 {
                proposal_binding_hash: descriptor.binding_hash().unwrap(),
                member_index,
                voter,
                signature_suite: SignatureSuite::ML_DSA_44,
                signature: keypair.sign(&preimage).unwrap().to_bytes(),
            };
            certificate = pool.insert(vote, &set, &registry).unwrap();
        }
        let certificate = certificate.unwrap();
        let verified = verify_async_proposal_availability_certificate(
            &certificate,
            &instance,
            &set,
            &registry,
        )
        .unwrap();
        assert_eq!(verified.holders.len(), 3);
        let reference = certificate.proposal_ref(&instance).unwrap();
        reference
            .validate_availability_binding(&instance, &certificate)
            .unwrap();
    }

    #[test]
    fn availability_certificate_refuses_payload_and_instance_rebinding() {
        let (decision, _, set, registry, keypairs) = fixture();
        let instance = decision.instance;
        let descriptor = AftAsyncProposalDescriptorV1 {
            instance_hash: instance.instance_hash().unwrap(),
            proposer: 0,
            proposal_hash: [0x61; 32],
            payload_len: 8192,
            parent_root: instance.locked_root,
        };
        let mut pool =
            AsyncProposalAvailabilityVotePool::new(instance.clone(), descriptor.clone()).unwrap();
        let mut certificate = None;
        for (index, keypair) in keypairs.iter().take(3).enumerate() {
            let voter = set.validators[index].account_id;
            let preimage =
                AftAsyncProposalAvailabilityVoteV1::signing_bytes(&descriptor, index as u16, voter)
                    .unwrap();
            certificate = pool
                .insert(
                    AftAsyncProposalAvailabilityVoteV1 {
                        proposal_binding_hash: descriptor.binding_hash().unwrap(),
                        member_index: index as u16,
                        voter,
                        signature_suite: SignatureSuite::ML_DSA_44,
                        signature: keypair.sign(&preimage).unwrap().to_bytes(),
                    },
                    &set,
                    &registry,
                )
                .unwrap();
        }
        let mut certificate = certificate.unwrap();
        certificate.descriptor.payload_len += 1;
        assert!(verify_async_proposal_availability_certificate(
            &certificate,
            &instance,
            &set,
            &registry,
        )
        .is_err());
        certificate.descriptor = descriptor;
        certificate.descriptor.instance_hash[0] ^= 1;
        assert!(verify_async_proposal_availability_certificate(
            &certificate,
            &instance,
            &set,
            &registry,
        )
        .is_err());
    }
}
