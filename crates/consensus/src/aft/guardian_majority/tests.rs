use super::*;
use async_trait::async_trait;
use ioi_api::chain::{AnchoredStateView, RemoteStateView};
use ioi_api::crypto::{SerializableKey, SigningKeyPair};
use ioi_crypto::sign::bls::BlsKeyPair;
use ioi_crypto::sign::guardian_committee::{
    canonical_manifest_hash, canonical_witness_manifest_hash, encode_signers_bitfield,
    sign_decision_with_members, sign_witness_statement_with_members,
};
use ioi_crypto::sign::guardian_log::{
    canonical_log_leaf_hash, checkpoint_root_from_leaf_hashes, checkpoint_signing_payload,
};
use ioi_types::app::ActiveKeyRecord;
use ioi_types::app::{
    aft_bulletin_availability_certificate_key, aft_bulletin_commitment_key,
    aft_canonical_bulletin_close_key, aft_canonical_collapse_object_key,
    aft_canonical_order_abort_key, aft_publication_frontier_key,
    build_bulletin_availability_certificate, build_canonical_bulletin_close,
    build_publication_frontier, build_reference_canonical_order_proof_bytes,
    canonical_asymptote_observer_assignments_hash, canonical_asymptote_observer_challenges_hash,
    canonical_asymptote_observer_transcripts_hash, canonical_collapse_commitment,
    canonical_collapse_commitment_hash_from_object, canonical_collapse_continuity_public_inputs,
    canonical_collapse_recursive_proof_hash, canonical_collapse_succinct_mock_proof_bytes,
    canonical_order_public_inputs, canonical_order_public_inputs_hash,
    canonical_sealed_finality_proof_signing_bytes, derive_asymptote_observer_assignments,
    derive_canonical_collapse_object, derive_canonical_collapse_object_with_previous,
    derive_guardian_witness_assignments, derive_reference_ordering_randomness_beacon,
    guardian_registry_asymptote_policy_key, guardian_registry_checkpoint_key,
    guardian_registry_committee_account_key, guardian_registry_committee_key,
    guardian_registry_log_key, guardian_registry_observer_canonical_abort_key,
    guardian_registry_observer_canonical_close_key,
    guardian_registry_observer_challenge_commitment_key,
    guardian_registry_observer_transcript_commitment_key, guardian_registry_witness_key,
    guardian_registry_witness_seed_key, guardian_registry_witness_set_key,
    recovered_restart_block_header_entry, write_validator_sets, AftRecoveredStateSurface,
    AsymptoteObserverCanonicalAbort, AsymptoteObserverCanonicalClose, AsymptoteObserverCertificate,
    AsymptoteObserverChallenge, AsymptoteObserverChallengeCommitment,
    AsymptoteObserverCloseCertificate, AsymptoteObserverCorrelationBudget,
    AsymptoteObserverTranscript, AsymptoteObserverTranscriptCommitment, AsymptoteObserverVerdict,
    AsymptotePolicy, AsymptoteVetoKind, AsymptoteVetoProof, BulletinAvailabilityCertificate,
    BulletinCommitment, CanonicalCollapseContinuityProofSystem, CanonicalOrderAbort,
    CanonicalOrderAbortReason, CanonicalOrderCertificate, CanonicalOrderProof,
    CanonicalOrderProofSystem, CollapseState, FinalityTier, GuardianCommitteeMember,
    GuardianLogCheckpoint, GuardianLogProof, GuardianTransparencyLogDescriptor,
    GuardianWitnessCommitteeManifest, GuardianWitnessRecoveryBinding, OmissionProof,
    RecoverableSlotPayloadV5, SealedFinalityProof, SignatureProof, SignatureSuite, StateRoot,
    ValidatorSetV1, ValidatorSetsV1, ValidatorV1,
};
use ioi_types::codec;
use ioi_types::error::ChainError;
use libp2p::identity::Keypair;
use std::collections::HashMap;
use std::sync::{Mutex as StdMutex, OnceLock};

fn sample_recovered_restart_entry(
    parent_header: &RecoveredCanonicalHeaderEntry,
    parent_qc: QuorumCertificate,
    parent_state_root: [u8; 32],
    height: u64,
    view: u64,
    block_seed: u8,
    tx_seed: u8,
    state_seed: u8,
    collapse_seed: u8,
    producer_seed: u8,
    bulletin_seed: u8,
) -> RecoveredRestartBlockHeaderEntry {
    let certified_entry = RecoveredCertifiedHeaderEntry {
        header: RecoveredCanonicalHeaderEntry {
            height,
            view,
            canonical_block_commitment_hash: [block_seed; 32],
            parent_block_commitment_hash: parent_header.canonical_block_commitment_hash,
            transactions_root_hash: [tx_seed; 32],
            resulting_state_root_hash: [state_seed; 32],
            previous_canonical_collapse_commitment_hash: [collapse_seed; 32],
        },
        certified_parent_quorum_certificate: parent_qc,
        certified_parent_resulting_state_root_hash: parent_state_root,
    };
    let payload = RecoverableSlotPayloadV5 {
        height,
        view,
        producer_account_id: AccountId([producer_seed; 32]),
        block_commitment_hash: certified_entry.header.canonical_block_commitment_hash,
        parent_block_hash: certified_entry.header.parent_block_commitment_hash,
        canonical_order_certificate: CanonicalOrderCertificate {
            height,
            bulletin_commitment: BulletinCommitment {
                height,
                cutoff_timestamp_ms: 1_760_000_000_000 + height * 1_000,
                bulletin_root: [bulletin_seed; 32],
                entry_count: 0,
            },
            bulletin_availability_certificate: BulletinAvailabilityCertificate {
                height,
                bulletin_commitment_hash: [bulletin_seed.wrapping_add(1); 32],
                recoverability_root: [bulletin_seed.wrapping_add(2); 32],
            },
            randomness_beacon: [bulletin_seed.wrapping_add(3); 32],
            ordered_transactions_root_hash: certified_entry.header.transactions_root_hash,
            resulting_state_root_hash: certified_entry.header.resulting_state_root_hash,
            proof: CanonicalOrderProof::default(),
            omission_proofs: Vec::new(),
        },
        ordered_transaction_bytes: Vec::new(),
        canonical_order_publication_bundle_bytes: Vec::new(),
        canonical_bulletin_close_bytes: Vec::new(),
        canonical_bulletin_availability_certificate_bytes: Vec::new(),
        bulletin_surface_entries: Vec::new(),
    };
    recovered_restart_block_header_entry(&payload, &certified_entry).expect("restart entry")
}

fn sample_recovered_restart_entry_branch(
    previous_header: &RecoveredCanonicalHeaderEntry,
    first_view: u64,
    depth: usize,
    seed_base: u8,
) -> Vec<RecoveredRestartBlockHeaderEntry> {
    let mut branch = Vec::with_capacity(depth);
    let mut parent_header = previous_header.clone();
    let mut parent_qc = previous_header.synthetic_quorum_certificate();
    let mut parent_state_root = previous_header.resulting_state_root_hash;
    for offset in 0..depth {
        let seed = seed_base.wrapping_add(offset as u8);
        let entry = sample_recovered_restart_entry(
            &parent_header,
            parent_qc.clone(),
            parent_state_root,
            previous_header.height + 1 + offset as u64,
            first_view + offset as u64,
            seed,
            seed.wrapping_add(0x10),
            seed.wrapping_add(0x20),
            seed.wrapping_add(0x30),
            seed.wrapping_add(0x40),
            seed.wrapping_add(0x50),
        );
        parent_header = entry.certified_header.header.clone();
        parent_qc = entry.certified_quorum_certificate();
        parent_state_root = entry.certified_header.header.resulting_state_root_hash;
        branch.push(entry);
    }
    branch
}

#[derive(Clone, Default)]
struct MockAnchoredView {
    state_root: Vec<u8>,
    state: HashMap<Vec<u8>, Vec<u8>>,
}

#[async_trait]
impl RemoteStateView for MockAnchoredView {
    async fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, ChainError> {
        Ok(self.state.get(key).cloned())
    }

    fn height(&self) -> u64 {
        0
    }

    fn state_root(&self) -> &[u8] {
        &self.state_root
    }
}

#[async_trait]
impl AnchoredStateView for MockAnchoredView {
    async fn gas_used(&self) -> Result<u64, ChainError> {
        Ok(0)
    }
}

fn build_log_descriptor(log_id: &str, keypair: &Keypair) -> GuardianTransparencyLogDescriptor {
    GuardianTransparencyLogDescriptor {
        log_id: log_id.into(),
        signature_suite: SignatureSuite::ED25519,
        public_key: keypair.public().encode_protobuf(),
    }
}

fn build_signed_checkpoint(
    log_id: &str,
    keypair: &Keypair,
    entries: &[Vec<u8>],
    leaf_index: usize,
    timestamp_ms: u64,
) -> GuardianLogCheckpoint {
    let leaf_hashes = entries
        .iter()
        .map(|entry| canonical_log_leaf_hash(entry).unwrap())
        .collect::<Vec<_>>();
    let root_hash = checkpoint_root_from_leaf_hashes(&leaf_hashes).unwrap();
    let mut checkpoint = GuardianLogCheckpoint {
        log_id: log_id.into(),
        tree_size: leaf_hashes.len() as u64,
        root_hash,
        timestamp_ms,
        signature: Vec::new(),
        proof: Some(GuardianLogProof {
            base_tree_size: 0,
            leaf_index: leaf_index as u64,
            leaf_hash: leaf_hashes[leaf_index],
            extension_leaf_hashes: leaf_hashes,
        }),
    };
    checkpoint.signature = keypair
        .sign(&checkpoint_signing_payload(&checkpoint).unwrap())
        .unwrap();
    checkpoint
}

fn build_case(
    signer_indexes: &[(usize, usize)],
) -> (
    GuardianMajorityEngine,
    BlockHeader,
    GuardianCommitteeManifest,
    Vec<u8>,
    Vec<BlsKeyPair>,
    Keypair,
) {
    let engine = GuardianMajorityEngine::new(AftSafetyMode::GuardianMajority);
    let log_keypair = Keypair::generate_ed25519();
    let member_keys = vec![
        BlsKeyPair::generate().unwrap(),
        BlsKeyPair::generate().unwrap(),
        BlsKeyPair::generate().unwrap(),
    ];
    let manifest = GuardianCommitteeManifest {
        validator_account_id: AccountId([7u8; 32]),
        epoch: 4,
        threshold: 2,
        members: member_keys
            .iter()
            .enumerate()
            .map(|(idx, keypair)| GuardianCommitteeMember {
                member_id: format!("member-{idx}"),
                signature_suite: SignatureSuite::BLS12_381,
                public_key: keypair.public_key().to_bytes(),
                endpoint: None,
                provider: None,
                region: None,
                host_class: None,
                key_authority_kind: None,
            })
            .collect(),
        measurement_profile_root: [22u8; 32],
        policy_hash: [33u8; 32],
        transparency_log_id: "guardian-test".into(),
    };

    let mut header = BlockHeader {
        height: 9,
        view: 2,
        parent_hash: [1u8; 32],
        parent_state_root: StateRoot(vec![2u8; 32]),
        state_root: StateRoot(vec![3u8; 32]),
        transactions_root: vec![4u8; 32],
        timestamp: 1234,
        timestamp_ms: 1_234_000,
        gas_used: 0,
        validator_set: Vec::new(),
        producer_account_id: manifest.validator_account_id,
        producer_key_suite: SignatureSuite::ED25519,
        producer_pubkey_hash: ioi_crypto::algorithms::hash::sha256(
            &log_keypair.public().encode_protobuf(),
        )
        .unwrap(),
        producer_pubkey: log_keypair.public().encode_protobuf(),
        oracle_counter: 0,
        oracle_trace_hash: [0u8; 32],
        guardian_certificate: None,
        sealed_finality_proof: None,
        canonical_order_certificate: None,
        parent_qc: QuorumCertificate::default(),
        previous_canonical_collapse_commitment_hash: [0u8; 32],
        canonical_collapse_extension_certificate: None,
        publication_frontier: None,
        timeout_certificate: None,
        signature: Vec::new(),
    };

    let preimage = header.to_preimage_for_signing().unwrap();
    let payload_hash = ioi_crypto::algorithms::hash::sha256(&preimage).unwrap();
    let decision = GuardianDecision {
        domain: GuardianDecisionDomain::ConsensusSlot as u8,
        subject: manifest.validator_account_id.0.to_vec(),
        payload_hash,
        counter: 3,
        trace_hash: [44u8; 32],
        measurement_root: manifest.measurement_profile_root,
        policy_hash: manifest.policy_hash,
    };
    let signer_keys = signer_indexes
        .iter()
        .map(|(member_index, key_index)| (*member_index, member_keys[*key_index].private_key()))
        .collect::<Vec<_>>();
    let certificate = sign_decision_with_members(
        &manifest,
        &decision,
        decision.counter,
        decision.trace_hash,
        &signer_keys,
    )
    .unwrap();
    header.oracle_counter = decision.counter;
    header.oracle_trace_hash = decision.trace_hash;
    let mut certificate = certificate;
    let checkpoint_entry =
        codec::to_bytes_canonical(&(decision.clone(), certificate.clone())).unwrap();
    certificate.log_checkpoint = Some(build_signed_checkpoint(
        &manifest.transparency_log_id,
        &log_keypair,
        &[checkpoint_entry],
        0,
        10,
    ));
    header.guardian_certificate = Some(certificate);

    (engine, header, manifest, preimage, member_keys, log_keypair)
}

fn sign_test_sealed_finality_proof(proof: &mut SealedFinalityProof, producer_keypair: &Keypair) {
    proof.proof_signature = SignatureProof::default();
    let sign_bytes = canonical_sealed_finality_proof_signing_bytes(proof).unwrap();
    proof.proof_signature = SignatureProof {
        suite: SignatureSuite::ED25519,
        public_key: producer_keypair.public().encode_protobuf(),
        signature: producer_keypair.sign(&sign_bytes).unwrap(),
    };
}

fn build_witness_manifest(member_keys: &[BlsKeyPair]) -> GuardianWitnessCommitteeManifest {
    GuardianWitnessCommitteeManifest {
        committee_id: "witness-a".into(),
        stratum_id: "stratum-a".into(),
        epoch: 4,
        threshold: 2,
        members: member_keys
            .iter()
            .enumerate()
            .map(|(idx, keypair)| GuardianCommitteeMember {
                member_id: format!("witness-{idx}"),
                signature_suite: SignatureSuite::BLS12_381,
                public_key: keypair.public_key().to_bytes(),
                endpoint: None,
                provider: None,
                region: None,
                host_class: None,
                key_authority_kind: None,
            })
            .collect(),
        policy_hash: [55u8; 32],
        transparency_log_id: "witness-test".into(),
    }
}

fn build_observer_manifest(
    observer_account_id: AccountId,
    epoch: u64,
    policy_hash: [u8; 32],
    transparency_log_id: &str,
    member_keys: &[BlsKeyPair],
) -> GuardianCommitteeManifest {
    GuardianCommitteeManifest {
        validator_account_id: observer_account_id,
        epoch,
        threshold: 2,
        members: member_keys
            .iter()
            .enumerate()
            .map(|(idx, keypair)| GuardianCommitteeMember {
                member_id: format!("observer-{idx}"),
                signature_suite: SignatureSuite::BLS12_381,
                public_key: keypair.public_key().to_bytes(),
                endpoint: None,
                provider: None,
                region: None,
                host_class: None,
                key_authority_kind: None,
            })
            .collect(),
        measurement_profile_root: [71u8; 32],
        policy_hash,
        transparency_log_id: transparency_log_id.into(),
    }
}

struct CanonicalObserverFixture {
    engine: GuardianMajorityEngine,
    header: BlockHeader,
    manifest: GuardianCommitteeManifest,
    preimage: Vec<u8>,
    guardian_log_keypair: Keypair,
    policy: AsymptotePolicy,
    witness_seed: GuardianWitnessEpochSeed,
    validators: Vec<AccountId>,
    observer_manifests: Vec<GuardianCommitteeManifest>,
    observer_descriptors: Vec<GuardianTransparencyLogDescriptor>,
    anchored_checkpoints: Vec<GuardianLogCheckpoint>,
    observer_assignments: Vec<AsymptoteObserverAssignment>,
    observer_transcripts: Vec<AsymptoteObserverTranscript>,
}

fn build_canonical_observer_fixture() -> CanonicalObserverFixture {
    let (mut engine, header, manifest, preimage, _, guardian_log_keypair) =
        build_case(&[(0, 0), (1, 1)]);
    engine.safety_mode = AftSafetyMode::Asymptote;
    let guardian_log_descriptor =
        build_log_descriptor(&manifest.transparency_log_id, &guardian_log_keypair);
    let witness_seed = GuardianWitnessEpochSeed {
        epoch: manifest.epoch,
        seed: [111u8; 32],
        checkpoint_interval_blocks: 1,
        max_reassignment_depth: 0,
    };
    let policy = AsymptotePolicy {
        epoch: manifest.epoch,
        high_risk_effect_tier: FinalityTier::SealedFinal,
        required_witness_strata: Vec::new(),
        escalation_witness_strata: Vec::new(),
        observer_rounds: 2,
        observer_committee_size: 1,
        observer_correlation_budget: AsymptoteObserverCorrelationBudget::default(),
        observer_sealing_mode: AsymptoteObserverSealingMode::CanonicalChallengeV1,
        observer_challenge_window_ms: 5_000,
        max_reassignment_depth: 0,
        max_checkpoint_staleness_ms: 120_000,
    };
    let validators = vec![
        header.producer_account_id,
        AccountId([61u8; 32]),
        AccountId([62u8; 32]),
        AccountId([63u8; 32]),
    ];
    let observer_assignments = derive_asymptote_observer_assignments(
        &witness_seed,
        &build_validator_sets(validators.clone()).current,
        header.producer_account_id,
        header.height,
        header.view,
        policy.observer_rounds,
        policy.observer_committee_size,
    )
    .unwrap();

    let observer_log_keypair = Keypair::generate_ed25519();
    let mut observer_manifests = Vec::new();
    let mut observer_descriptors = vec![guardian_log_descriptor];
    let mut anchored_checkpoints = vec![header
        .guardian_certificate
        .as_ref()
        .unwrap()
        .log_checkpoint
        .as_ref()
        .unwrap()
        .clone()];
    let base_certificate = header.guardian_certificate.as_ref().unwrap().clone();
    let selected_accounts = observer_assignments
        .iter()
        .map(|assignment| assignment.observer_account_id)
        .collect::<std::collections::HashSet<_>>();
    let mut selected_manifests = HashMap::new();
    for account in validators
        .iter()
        .copied()
        .filter(|account| *account != header.producer_account_id)
    {
        let member_keys = vec![
            BlsKeyPair::generate().unwrap(),
            BlsKeyPair::generate().unwrap(),
            BlsKeyPair::generate().unwrap(),
        ];
        let log_id = format!(
            "observer-canonical-fixture-{}",
            hex::encode(account.as_ref())
        );
        let observer_manifest =
            build_observer_manifest(account, manifest.epoch, [91u8; 32], &log_id, &member_keys);
        if selected_accounts.contains(&account) {
            selected_manifests.insert(account, (observer_manifest.clone(), member_keys));
        }
        observer_manifests.push(observer_manifest);
    }

    let mut observer_transcripts = Vec::new();
    for assignment in observer_assignments.iter().cloned() {
        let (observer_manifest, member_keys) = selected_manifests
            .remove(&assignment.observer_account_id)
            .unwrap();
        let provisional = AsymptoteObserverCertificate {
            assignment: assignment.clone(),
            verdict: AsymptoteObserverVerdict::Ok,
            veto_kind: None,
            evidence_hash: [0u8; 32],
            guardian_certificate: GuardianQuorumCertificate::default(),
        };
        let statement = engine
            .asymptote_observer_statement(&header, &base_certificate, &provisional)
            .unwrap();
        let decision = GuardianDecision {
            domain: GuardianDecisionDomain::AsymptoteObserve as u8,
            subject: assignment.observer_account_id.0.to_vec(),
            payload_hash: ioi_crypto::algorithms::hash::sha256(
                &codec::to_bytes_canonical(&statement).unwrap(),
            )
            .unwrap(),
            counter: u64::from(assignment.round) + 1,
            trace_hash: [assignment.round as u8 + 21; 32],
            measurement_root: observer_manifest.measurement_profile_root,
            policy_hash: observer_manifest.policy_hash,
        };
        let mut observer_guardian_certificate = sign_decision_with_members(
            &observer_manifest,
            &decision,
            decision.counter,
            decision.trace_hash,
            &[
                (0, member_keys[0].private_key()),
                (1, member_keys[1].private_key()),
            ],
        )
        .unwrap();
        let checkpoint_entry =
            codec::to_bytes_canonical(&(decision.clone(), observer_guardian_certificate.clone()))
                .unwrap();
        observer_guardian_certificate.log_checkpoint = Some(build_signed_checkpoint(
            &observer_manifest.transparency_log_id,
            &observer_log_keypair,
            &[checkpoint_entry],
            0,
            u64::from(assignment.round) + 80,
        ));
        anchored_checkpoints.push(
            observer_guardian_certificate
                .log_checkpoint
                .as_ref()
                .unwrap()
                .clone(),
        );
        observer_descriptors.push(build_log_descriptor(
            &observer_manifest.transparency_log_id,
            &observer_log_keypair,
        ));
        observer_transcripts.push(AsymptoteObserverTranscript {
            statement,
            guardian_certificate: observer_guardian_certificate,
        });
    }

    CanonicalObserverFixture {
        engine,
        header,
        manifest,
        preimage,
        guardian_log_keypair,
        policy,
        witness_seed,
        validators,
        observer_manifests,
        observer_descriptors,
        anchored_checkpoints,
        observer_assignments,
        observer_transcripts,
    }
}

fn canonical_observer_parent_view(fixture: &CanonicalObserverFixture) -> MockAnchoredView {
    build_parent_view_with_asymptote_observers(
        &fixture.manifest,
        &fixture.observer_descriptors,
        fixture.policy.clone(),
        fixture.witness_seed.clone(),
        &fixture.anchored_checkpoints,
        fixture.validators.clone(),
        &fixture.observer_manifests,
    )
}

fn finalize_observer_challenge_id(challenge: &mut AsymptoteObserverChallenge) {
    let mut normalized = challenge.clone();
    normalized.challenge_id = [0u8; 32];
    challenge.challenge_id =
        ioi_crypto::algorithms::hash::sha256(&codec::to_bytes_canonical(&normalized).unwrap())
            .unwrap();
}

fn build_parent_view(
    committee_manifest: &GuardianCommitteeManifest,
    log_descriptors: &[GuardianTransparencyLogDescriptor],
    witness_manifests: &[GuardianWitnessCommitteeManifest],
    witness_set: GuardianWitnessSet,
    witness_seed: GuardianWitnessEpochSeed,
    anchored_checkpoints: &[GuardianLogCheckpoint],
) -> MockAnchoredView {
    let mut state = HashMap::new();
    let manifest_hash =
        ioi_crypto::sign::guardian_committee::canonical_manifest_hash(committee_manifest).unwrap();
    state.insert(
        guardian_registry_committee_key(&manifest_hash),
        codec::to_bytes_canonical(committee_manifest).unwrap(),
    );
    for descriptor in log_descriptors {
        state.insert(
            guardian_registry_log_key(&descriptor.log_id),
            codec::to_bytes_canonical(descriptor).unwrap(),
        );
    }
    for witness_manifest in witness_manifests {
        let witness_hash = canonical_witness_manifest_hash(witness_manifest).unwrap();
        state.insert(
            guardian_registry_witness_key(&witness_hash),
            codec::to_bytes_canonical(witness_manifest).unwrap(),
        );
    }
    state.insert(
        guardian_registry_witness_set_key(witness_set.epoch),
        codec::to_bytes_canonical(&witness_set).unwrap(),
    );
    state.insert(
        guardian_registry_witness_seed_key(witness_seed.epoch),
        codec::to_bytes_canonical(&witness_seed).unwrap(),
    );
    state.insert(
        CURRENT_EPOCH_KEY.to_vec(),
        codec::to_bytes_canonical(&committee_manifest.epoch).unwrap(),
    );
    for checkpoint in anchored_checkpoints {
        state.insert(
            guardian_registry_checkpoint_key(&checkpoint.log_id),
            codec::to_bytes_canonical(checkpoint).unwrap(),
        );
    }

    MockAnchoredView {
        state_root: vec![9u8; 32],
        state,
    }
}

fn build_parent_view_with_asymptote_policy(
    committee_manifest: &GuardianCommitteeManifest,
    log_descriptors: &[GuardianTransparencyLogDescriptor],
    witness_manifests: &[GuardianWitnessCommitteeManifest],
    witness_set: GuardianWitnessSet,
    witness_seed: GuardianWitnessEpochSeed,
    anchored_checkpoints: &[GuardianLogCheckpoint],
    policy: AsymptotePolicy,
) -> MockAnchoredView {
    let mut view = build_parent_view(
        committee_manifest,
        log_descriptors,
        witness_manifests,
        witness_set,
        witness_seed,
        anchored_checkpoints,
    );
    view.state.insert(
        guardian_registry_asymptote_policy_key(policy.epoch),
        codec::to_bytes_canonical(&policy).unwrap(),
    );
    view
}

fn build_parent_view_with_bulletin_commitment(
    committee_manifest: &GuardianCommitteeManifest,
    log_descriptors: &[GuardianTransparencyLogDescriptor],
    policy: AsymptotePolicy,
    witness_seed: GuardianWitnessEpochSeed,
    anchored_checkpoints: &[GuardianLogCheckpoint],
    bulletin_commitment: BulletinCommitment,
) -> MockAnchoredView {
    let mut view = build_parent_view_with_asymptote_policy(
        committee_manifest,
        log_descriptors,
        &[],
        GuardianWitnessSet {
            epoch: witness_seed.epoch,
            manifest_hashes: Vec::new(),
            checkpoint_interval_blocks: witness_seed.checkpoint_interval_blocks,
        },
        witness_seed,
        anchored_checkpoints,
        policy,
    );
    view.state.insert(
        aft_bulletin_commitment_key(bulletin_commitment.height),
        codec::to_bytes_canonical(&bulletin_commitment).unwrap(),
    );
    view
}

fn build_validator_sets(validators: Vec<AccountId>) -> ValidatorSetsV1 {
    ValidatorSetsV1 {
        current: ValidatorSetV1 {
            effective_from_height: 1,
            total_weight: validators.len() as u128,
            validators: validators
                .into_iter()
                .map(|account_id| ValidatorV1 {
                    account_id,
                    weight: 1,
                    consensus_key: ActiveKeyRecord {
                        suite: SignatureSuite::ED25519,
                        public_key_hash: account_id.0,
                        since_height: 1,
                    },
                })
                .collect(),
        },
        next: None,
    }
}

fn build_parent_view_with_asymptote_observers(
    committee_manifest: &GuardianCommitteeManifest,
    log_descriptors: &[GuardianTransparencyLogDescriptor],
    policy: AsymptotePolicy,
    witness_seed: GuardianWitnessEpochSeed,
    anchored_checkpoints: &[GuardianLogCheckpoint],
    validators: Vec<AccountId>,
    additional_guardian_manifests: &[GuardianCommitteeManifest],
) -> MockAnchoredView {
    let mut view = build_parent_view_with_asymptote_policy(
        committee_manifest,
        log_descriptors,
        &[],
        GuardianWitnessSet {
            epoch: witness_seed.epoch,
            manifest_hashes: Vec::new(),
            checkpoint_interval_blocks: witness_seed.checkpoint_interval_blocks,
        },
        witness_seed,
        anchored_checkpoints,
        policy,
    );
    for observer_manifest in additional_guardian_manifests {
        let manifest_hash = canonical_manifest_hash(observer_manifest).unwrap();
        view.state.insert(
            guardian_registry_committee_key(&manifest_hash),
            codec::to_bytes_canonical(observer_manifest).unwrap(),
        );
        view.state.insert(
            guardian_registry_committee_account_key(&observer_manifest.validator_account_id),
            manifest_hash.to_vec(),
        );
    }
    view.state.insert(
        VALIDATOR_SET_KEY.to_vec(),
        write_validator_sets(&build_validator_sets(validators)).unwrap(),
    );
    view
}

fn build_decide_parent_view(validators: Vec<AccountId>) -> MockAnchoredView {
    let mut view = MockAnchoredView::default();
    view.state.insert(
        VALIDATOR_SET_KEY.to_vec(),
        write_validator_sets(&build_validator_sets(validators)).unwrap(),
    );
    view.state.insert(
        BLOCK_TIMING_PARAMS_KEY.to_vec(),
        codec::to_bytes_canonical(&BlockTimingParams::default()).unwrap(),
    );
    view.state.insert(
        BLOCK_TIMING_RUNTIME_KEY.to_vec(),
        codec::to_bytes_canonical(&BlockTimingRuntime::default()).unwrap(),
    );
    view.state.insert(
        STATUS_KEY.to_vec(),
        codec::to_bytes_canonical(&ChainStatus::default()).unwrap(),
    );
    view
}

fn build_progress_parent_header(height: u64, view: u64) -> BlockHeader {
    BlockHeader {
        height,
        view,
        parent_hash: [height.saturating_sub(1) as u8; 32],
        parent_state_root: StateRoot(vec![height.saturating_sub(1) as u8; 32]),
        state_root: StateRoot(vec![height as u8 + 10; 32]),
        transactions_root: vec![height as u8 + 20; 32],
        timestamp: height,
        timestamp_ms: height.saturating_mul(1_000),
        gas_used: 0,
        validator_set: Vec::new(),
        producer_account_id: AccountId([height as u8 + 30; 32]),
        producer_key_suite: SignatureSuite::ED25519,
        producer_pubkey_hash: [height as u8 + 31; 32],
        producer_pubkey: vec![height as u8 + 32; 32],
        oracle_counter: height,
        oracle_trace_hash: [height as u8 + 33; 32],
        guardian_certificate: None,
        sealed_finality_proof: None,
        canonical_order_certificate: None,
        parent_qc: if height > 1 {
            QuorumCertificate {
                height: height - 1,
                view,
                block_hash: [height.saturating_sub(1) as u8; 32],
                signatures: vec![],
                aggregated_signature: vec![],
                signers_bitfield: vec![],
            }
        } else {
            QuorumCertificate::default()
        },
        previous_canonical_collapse_commitment_hash: [0u8; 32],
        canonical_collapse_extension_certificate: None,
        publication_frontier: None,
        timeout_certificate: None,
        signature: vec![height as u8 + 34; 64],
    }
}

fn extension_certificate_from_predecessor(
    predecessor: &CanonicalCollapseObject,
    covered_height: u64,
) -> CanonicalCollapseExtensionCertificate {
    canonical_collapse_extension_certificate(covered_height, predecessor)
        .expect("extension certificate")
}

fn continuity_env_lock() -> &'static StdMutex<()> {
    static LOCK: OnceLock<StdMutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| StdMutex::new(()))
}

fn test_canonical_collapse_object(
    height: u64,
    previous: Option<&CanonicalCollapseObject>,
    transactions_root_hash: [u8; 32],
    resulting_state_root_hash: [u8; 32],
) -> CanonicalCollapseObject {
    let mut collapse = CanonicalCollapseObject {
        height,
        previous_canonical_collapse_commitment_hash: [0u8; 32],
        continuity_accumulator_hash: [0u8; 32],
        continuity_recursive_proof: Default::default(),
        ordering: Default::default(),
        sealing: None,
        transactions_root_hash,
        resulting_state_root_hash,
        archived_recovered_history_checkpoint_hash: [0u8; 32],
        archived_recovered_history_profile_activation_hash: [0u8; 32],
        archived_recovered_history_retention_receipt_hash: [0u8; 32],
    };
    bind_canonical_collapse_continuity(&mut collapse, previous)
        .expect("bind test canonical collapse continuity");
    collapse
}

fn bind_succinct_mock_continuity(collapse: &mut CanonicalCollapseObject) {
    let proof = &mut collapse.continuity_recursive_proof;
    let public_inputs = canonical_collapse_continuity_public_inputs(
        &proof.commitment,
        proof.previous_canonical_collapse_commitment_hash,
        proof.payload_hash,
        proof.previous_recursive_proof_hash,
    );
    proof.proof_system = CanonicalCollapseContinuityProofSystem::SuccinctSp1V1;
    proof.proof_bytes = canonical_collapse_succinct_mock_proof_bytes(&public_inputs)
        .expect("succinct mock proof bytes");
}

fn link_header_to_previous_collapse(header: &mut BlockHeader, previous: &CanonicalCollapseObject) {
    header.previous_canonical_collapse_commitment_hash =
        canonical_collapse_commitment_hash_from_object(previous).unwrap();
    header.canonical_collapse_extension_certificate = Some(extension_certificate_from_predecessor(
        previous,
        header.height,
    ));
    header.parent_state_root = StateRoot(previous.resulting_state_root_hash.to_vec());
}

fn link_header_to_collapse_chain(header: &mut BlockHeader, chain: &[CanonicalCollapseObject]) {
    let previous = chain
        .first()
        .expect("collapse chain requires at least one object");
    header.previous_canonical_collapse_commitment_hash =
        canonical_collapse_commitment_hash_from_object(previous).unwrap();
    header.canonical_collapse_extension_certificate = Some(extension_certificate_from_predecessor(
        previous,
        header.height,
    ));
    header.parent_state_root = StateRoot(previous.resulting_state_root_hash.to_vec());
}

#[test]
fn verify_canonical_collapse_backend_accepts_and_rejects_succinct_mock_proofs() {
    let engine = GuardianMajorityEngine::new(AftSafetyMode::Asymptote);
    let mut collapse = test_canonical_collapse_object(1, None, [0x21u8; 32], [0x22u8; 32]);
    let proof = &mut collapse.continuity_recursive_proof;
    let public_inputs = canonical_collapse_continuity_public_inputs(
        &proof.commitment,
        proof.previous_canonical_collapse_commitment_hash,
        proof.payload_hash,
        proof.previous_recursive_proof_hash,
    );
    proof.proof_system = CanonicalCollapseContinuityProofSystem::SuccinctSp1V1;
    proof.proof_bytes = canonical_collapse_succinct_mock_proof_bytes(&public_inputs)
        .expect("succinct mock proof bytes");

    engine
        .verify_canonical_collapse_backend(&collapse)
        .expect("succinct backend proof should verify");

    let mut mutated = collapse.clone();
    mutated.continuity_recursive_proof.proof_bytes[0] ^= 0xFF;
    assert!(engine.verify_canonical_collapse_backend(&mutated).is_err());
}

#[test]
fn verifies_valid_guardian_certificate() {
    let (engine, header, manifest, preimage, _, _) = build_case(&[(0, 0), (1, 1)]);
    engine
        .verify_guardianized_certificate_against_manifest(&header, &preimage, &manifest)
        .unwrap();
}

#[tokio::test]
async fn local_timeout_does_not_enter_new_view_without_timeout_certificate() {
    let validators = vec![
        AccountId([1u8; 32]),
        AccountId([2u8; 32]),
        AccountId([3u8; 32]),
    ];
    let parent_view = build_decide_parent_view(validators.clone());
    let known_peers = HashSet::from([PeerId::random()]);
    let mut engine =
        GuardianMajorityEngine::with_view_timeout(AftSafetyMode::GuardianMajority, Duration::ZERO);

    let first: ConsensusDecision<ChainTransaction> = engine
        .decide(&validators[0], 1, 0, &parent_view, &known_peers)
        .await;
    assert!(matches!(
        first,
        ConsensusDecision::Timeout { view: 1, height: 1 }
    ));
    assert_eq!(engine.pacemaker.lock().await.current_view, 0);

    let second: ConsensusDecision<ChainTransaction> = engine
        .decide(&validators[0], 1, 0, &parent_view, &known_peers)
        .await;
    assert!(matches!(second, ConsensusDecision::WaitForBlock));
    assert_eq!(engine.pacemaker.lock().await.current_view, 0);
}

#[tokio::test]
async fn bootstrap_grace_pins_view_zero_without_blocking_leader_production() {
    let validators = vec![
        AccountId([1u8; 32]),
        AccountId([2u8; 32]),
        AccountId([3u8; 32]),
    ];
    let parent_view = build_decide_parent_view(validators.clone());
    let known_peers = HashSet::from([PeerId::random()]);
    let mut engine = GuardianMajorityEngine::with_view_timeout(
        AftSafetyMode::GuardianMajority,
        Duration::from_secs(5),
    );
    engine.bootstrap_grace_until = Instant::now() + Duration::from_secs(60);

    let decision: ConsensusDecision<ChainTransaction> = engine
        .decide(&validators[1], 2, 0, &parent_view, &known_peers)
        .await;
    assert!(matches!(
        decision,
        ConsensusDecision::ProduceBlock { view: 0, .. }
    ));
    assert_eq!(engine.pacemaker.lock().await.current_view, 0);
}

#[tokio::test]
async fn asymptote_decide_times_out_when_parent_qc_is_not_collapse_backed() {
    let validators = vec![
        AccountId([1u8; 32]),
        AccountId([2u8; 32]),
        AccountId([3u8; 32]),
    ];
    let parent_view = build_decide_parent_view(validators.clone());
    let known_peers = HashSet::from([PeerId::random()]);
    let mut engine =
        GuardianMajorityEngine::with_view_timeout(AftSafetyMode::Asymptote, Duration::from_secs(5));
    engine.bootstrap_grace_until = Instant::now() + Duration::from_secs(60);
    engine.highest_qc = QuorumCertificate {
        height: 1,
        view: 0,
        block_hash: [77u8; 32],
        signatures: vec![
            (validators[0], vec![1u8; 64]),
            (validators[1], vec![2u8; 64]),
        ],
        aggregated_signature: vec![],
        signers_bitfield: vec![],
    };

    let decision: ConsensusDecision<ChainTransaction> = engine
        .decide(&validators[1], 2, 0, &parent_view, &known_peers)
        .await;
    assert!(matches!(
        decision,
        ConsensusDecision::Timeout { view: 1, height: 2 }
    ));
}

#[tokio::test]
async fn asymptote_decide_produces_when_parent_is_collapse_backed() {
    let validators = vec![
        AccountId([1u8; 32]),
        AccountId([2u8; 32]),
        AccountId([3u8; 32]),
    ];
    let known_peers = HashSet::from([PeerId::random()]);
    let mut parent_view = build_decide_parent_view(validators.clone());
    let mut engine =
        GuardianMajorityEngine::with_view_timeout(AftSafetyMode::Asymptote, Duration::from_secs(5));
    engine.bootstrap_grace_until = Instant::now() + Duration::from_secs(60);

    let parent_header = build_progress_parent_header(1, 0);
    let parent_hash = to_root_hash(&parent_header.hash().unwrap()).unwrap();
    let collapse = derive_canonical_collapse_object(&parent_header, &[]).unwrap();
    let collapse_commitment_hash =
        canonical_collapse_commitment_hash_from_object(&collapse).unwrap();
    parent_view.state.insert(
        aft_canonical_collapse_object_key(parent_header.height),
        codec::to_bytes_canonical(&collapse).unwrap(),
    );
    engine
        .committed_headers
        .insert(parent_header.height, parent_header.clone());
    engine
        .seen_headers
        .entry((parent_header.height, parent_header.view))
        .or_default()
        .insert(parent_hash, parent_header.clone());
    engine.highest_qc = QuorumCertificate {
        height: 1,
        view: 0,
        block_hash: parent_hash,
        signatures: vec![
            (validators[0], vec![1u8; 64]),
            (validators[1], vec![2u8; 64]),
        ],
        aggregated_signature: vec![],
        signers_bitfield: vec![],
    };

    let decision: ConsensusDecision<ChainTransaction> = engine
        .decide(&validators[1], 2, 0, &parent_view, &known_peers)
        .await;
    assert!(matches!(
        decision,
        ConsensusDecision::ProduceBlock {
            view: 0,
            previous_canonical_collapse_commitment_hash,
            canonical_collapse_extension_certificate,
            ..
        } if previous_canonical_collapse_commitment_hash == collapse_commitment_hash
            && canonical_collapse_extension_certificate.as_ref()
                == Some(&extension_certificate_from_predecessor(&collapse, 2))
    ));
}

#[tokio::test]
async fn asymptote_decide_produces_canonical_collapse_extension_certificate_when_available() {
    let validators = vec![
        AccountId([1u8; 32]),
        AccountId([2u8; 32]),
        AccountId([3u8; 32]),
    ];
    let known_peers = HashSet::from([PeerId::random()]);
    let mut parent_view = build_decide_parent_view(validators.clone());
    let mut engine =
        GuardianMajorityEngine::with_view_timeout(AftSafetyMode::Asymptote, Duration::from_secs(5));
    engine.bootstrap_grace_until = Instant::now() + Duration::from_secs(60);

    let grandparent_header = build_progress_parent_header(1, 0);
    let grandparent_collapse = derive_canonical_collapse_object(&grandparent_header, &[]).unwrap();
    parent_view.state.insert(
        aft_canonical_collapse_object_key(grandparent_header.height),
        codec::to_bytes_canonical(&grandparent_collapse).unwrap(),
    );

    let mut parent_header = build_progress_parent_header(2, 0);
    link_header_to_previous_collapse(&mut parent_header, &grandparent_collapse);
    let parent_hash = to_root_hash(&parent_header.hash().unwrap()).unwrap();
    let parent_collapse = derive_canonical_collapse_object_with_previous(
        &parent_header,
        &[],
        Some(&grandparent_collapse),
    )
    .unwrap();
    let parent_collapse_commitment_hash =
        canonical_collapse_commitment_hash_from_object(&parent_collapse).unwrap();
    parent_view.state.insert(
        aft_canonical_collapse_object_key(parent_header.height),
        codec::to_bytes_canonical(&parent_collapse).unwrap(),
    );
    engine
        .committed_headers
        .insert(parent_header.height, parent_header.clone());
    engine
        .seen_headers
        .entry((parent_header.height, parent_header.view))
        .or_default()
        .insert(parent_hash, parent_header);
    engine.highest_qc = QuorumCertificate {
        height: 2,
        view: 0,
        block_hash: parent_hash,
        signatures: vec![
            (validators[0], vec![1u8; 64]),
            (validators[1], vec![2u8; 64]),
        ],
        aggregated_signature: vec![],
        signers_bitfield: vec![],
    };

    let decision: ConsensusDecision<ChainTransaction> = engine
        .decide(&validators[2], 3, 0, &parent_view, &known_peers)
        .await;
    assert!(matches!(
        decision,
        ConsensusDecision::ProduceBlock {
            view: 0,
            previous_canonical_collapse_commitment_hash,
            canonical_collapse_extension_certificate,
            ..
        } if previous_canonical_collapse_commitment_hash == parent_collapse_commitment_hash
            && canonical_collapse_extension_certificate.as_ref()
                == Some(&extension_certificate_from_predecessor(&parent_collapse, 3))
    ));
}

#[tokio::test]
async fn asymptote_decide_stalls_when_previous_collapse_is_missing_for_current_height() {
    let validators = vec![
        AccountId([1u8; 32]),
        AccountId([2u8; 32]),
        AccountId([3u8; 32]),
    ];
    let known_peers = HashSet::from([PeerId::random()]);
    let mut parent_view = build_decide_parent_view(validators.clone());
    let mut engine =
        GuardianMajorityEngine::with_view_timeout(AftSafetyMode::Asymptote, Duration::from_secs(5));
    engine.bootstrap_grace_until = Instant::now() + Duration::from_secs(60);

    let parent_of_parent_header = build_progress_parent_header(1, 0);
    let parent_of_parent_collapse =
        derive_canonical_collapse_object(&parent_of_parent_header, &[]).unwrap();
    parent_view.state.insert(
        aft_canonical_collapse_object_key(parent_of_parent_header.height),
        codec::to_bytes_canonical(&parent_of_parent_collapse).unwrap(),
    );

    let mut parent_header = build_progress_parent_header(2, 0);
    link_header_to_previous_collapse(&mut parent_header, &parent_of_parent_collapse);
    let parent_hash = to_root_hash(&parent_header.hash().unwrap()).unwrap();
    engine
        .seen_headers
        .entry((parent_header.height, parent_header.view))
        .or_default()
        .insert(parent_hash, parent_header.clone());
    engine.highest_qc = QuorumCertificate {
        height: 2,
        view: 0,
        block_hash: parent_hash,
        signatures: vec![
            (validators[0], vec![1u8; 64]),
            (validators[1], vec![2u8; 64]),
        ],
        aggregated_signature: vec![],
        signers_bitfield: vec![],
    };

    let decision: ConsensusDecision<ChainTransaction> = engine
        .decide(&validators[2], 3, 0, &parent_view, &known_peers)
        .await;
    assert!(matches!(decision, ConsensusDecision::Stall));
}

#[tokio::test]
async fn asymptote_defers_ready_commit_until_parent_is_collapse_backed() {
    let validators = vec![
        AccountId([1u8; 32]),
        AccountId([2u8; 32]),
        AccountId([3u8; 32]),
    ];
    let known_peers = HashSet::from([PeerId::random()]);
    let parent_view = build_decide_parent_view(validators.clone());
    let mut engine =
        GuardianMajorityEngine::with_view_timeout(AftSafetyMode::Asymptote, Duration::from_secs(5));
    engine.bootstrap_grace_until = Instant::now() + Duration::from_secs(60);
    engine.safety = SafetyGadget::new().with_guard_duration(Duration::ZERO);

    let parent_qc = QuorumCertificate {
        height: 1,
        view: 0,
        block_hash: [77u8; 32],
        signatures: vec![
            (validators[0], vec![1u8; 64]),
            (validators[1], vec![2u8; 64]),
        ],
        aggregated_signature: vec![],
        signers_bitfield: vec![],
    };
    engine.highest_qc = parent_qc.clone();
    assert!(engine.safety.update(
        &QuorumCertificate {
            height: 2,
            view: 1,
            block_hash: [90u8; 32],
            signatures: vec![],
            aggregated_signature: vec![],
            signers_bitfield: vec![],
        },
        &parent_qc,
    ));

    let _: ConsensusDecision<ChainTransaction> = engine
        .decide(&validators[1], 2, 0, &parent_view, &known_peers)
        .await;
    assert!(engine.safety.committed_qc.is_none());
    assert!(engine.safety.next_ready_commit().is_some());
}

#[tokio::test]
async fn asymptote_accepts_ready_commit_once_parent_is_collapse_backed() {
    let validators = vec![
        AccountId([1u8; 32]),
        AccountId([2u8; 32]),
        AccountId([3u8; 32]),
    ];
    let known_peers = HashSet::from([PeerId::random()]);
    let mut parent_view = build_decide_parent_view(validators.clone());
    let mut engine =
        GuardianMajorityEngine::with_view_timeout(AftSafetyMode::Asymptote, Duration::from_secs(5));
    engine.bootstrap_grace_until = Instant::now() + Duration::from_secs(60);
    engine.safety = SafetyGadget::new().with_guard_duration(Duration::ZERO);

    let parent_header = build_progress_parent_header(1, 0);
    let parent_hash = to_root_hash(&parent_header.hash().unwrap()).unwrap();
    let collapse = derive_canonical_collapse_object(&parent_header, &[]).unwrap();
    parent_view.state.insert(
        aft_canonical_collapse_object_key(parent_header.height),
        codec::to_bytes_canonical(&collapse).unwrap(),
    );
    engine
        .committed_headers
        .insert(parent_header.height, parent_header.clone());
    engine
        .seen_headers
        .entry((parent_header.height, parent_header.view))
        .or_default()
        .insert(parent_hash, parent_header.clone());
    let parent_qc = QuorumCertificate {
        height: 1,
        view: 0,
        block_hash: parent_hash,
        signatures: vec![
            (validators[0], vec![1u8; 64]),
            (validators[1], vec![2u8; 64]),
        ],
        aggregated_signature: vec![],
        signers_bitfield: vec![],
    };
    engine.highest_qc = parent_qc.clone();
    assert!(engine.safety.update(
        &QuorumCertificate {
            height: 2,
            view: 1,
            block_hash: [91u8; 32],
            signatures: vec![],
            aggregated_signature: vec![],
            signers_bitfield: vec![],
        },
        &parent_qc,
    ));

    let _: ConsensusDecision<ChainTransaction> = engine
        .decide(&validators[1], 2, 0, &parent_view, &known_peers)
        .await;
    assert_eq!(
        engine.safety.committed_qc.as_ref().map(|qc| qc.height),
        Some(1)
    );
    assert!(engine.safety.next_ready_commit().is_none());
}

#[test]
fn rejects_invalid_aggregate_signature() {
    let (engine, mut header, manifest, preimage, _, _) = build_case(&[(0, 0), (1, 1)]);
    header
        .guardian_certificate
        .as_mut()
        .unwrap()
        .aggregated_signature[0] ^= 0x01;
    let err = engine
        .verify_guardianized_certificate_against_manifest(&header, &preimage, &manifest)
        .unwrap_err();
    assert!(matches!(err, ConsensusError::BlockVerificationFailed(_)));
}

#[test]
fn rejects_signer_outside_committee() {
    let (engine, mut header, mut manifest, preimage, _, _) = build_case(&[(0, 0), (1, 1)]);
    manifest.members.truncate(2);
    header
        .guardian_certificate
        .as_mut()
        .unwrap()
        .signers_bitfield = encode_signers_bitfield(3, &[0, 2]).unwrap();
    let err = engine
        .verify_guardianized_certificate_against_manifest(&header, &preimage, &manifest)
        .unwrap_err();
    assert!(matches!(err, ConsensusError::BlockVerificationFailed(_)));
}

#[test]
fn rejects_insufficient_threshold() {
    let (_, header, manifest, preimage, member_keys, _) = build_case(&[(0, 0), (1, 1)]);
    let payload_hash = ioi_crypto::algorithms::hash::sha256(&preimage).unwrap();
    let decision = GuardianDecision {
        domain: GuardianDecisionDomain::ConsensusSlot as u8,
        subject: manifest.validator_account_id.0.to_vec(),
        payload_hash,
        counter: header.oracle_counter,
        trace_hash: header.oracle_trace_hash,
        measurement_root: manifest.measurement_profile_root,
        policy_hash: manifest.policy_hash,
    };
    let err = sign_decision_with_members(
        &manifest,
        &decision,
        decision.counter,
        decision.trace_hash,
        &[(0, member_keys[0].private_key())],
    )
    .unwrap_err();
    assert!(err.to_string().contains("insufficient local signers"));
}

#[test]
fn rejects_wrong_decision_hash() {
    let (engine, mut header, manifest, preimage, _, _) = build_case(&[(0, 0), (1, 1)]);
    header.guardian_certificate.as_mut().unwrap().decision_hash[0] ^= 0x11;
    let err = engine
        .verify_guardianized_certificate_against_manifest(&header, &preimage, &manifest)
        .unwrap_err();
    assert!(matches!(err, ConsensusError::BlockVerificationFailed(_)));
}

#[test]
fn rejects_wrong_epoch() {
    let (engine, mut header, manifest, preimage, _, _) = build_case(&[(0, 0), (1, 1)]);
    header.guardian_certificate.as_mut().unwrap().epoch += 1;
    let err = engine
        .verify_guardianized_certificate_against_manifest(&header, &preimage, &manifest)
        .unwrap_err();
    assert!(matches!(err, ConsensusError::BlockVerificationFailed(_)));
}

#[test]
fn rejects_wrong_manifest_hash() {
    let (engine, mut header, manifest, preimage, _, _) = build_case(&[(0, 0), (1, 1)]);
    header.guardian_certificate.as_mut().unwrap().manifest_hash[0] ^= 0x55;
    let err = engine
        .verify_guardianized_certificate_against_manifest(&header, &preimage, &manifest)
        .unwrap_err();
    assert!(matches!(err, ConsensusError::BlockVerificationFailed(_)));
}

#[test]
fn duplicate_signer_indexes_are_rejected_before_certificate_construction() {
    let member_keys = vec![
        BlsKeyPair::generate().unwrap(),
        BlsKeyPair::generate().unwrap(),
    ];
    let manifest = GuardianCommitteeManifest {
        validator_account_id: AccountId([8u8; 32]),
        epoch: 1,
        threshold: 2,
        members: member_keys
            .iter()
            .enumerate()
            .map(|(idx, keypair)| GuardianCommitteeMember {
                member_id: format!("member-{idx}"),
                signature_suite: SignatureSuite::BLS12_381,
                public_key: keypair.public_key().to_bytes(),
                endpoint: None,
                provider: None,
                region: None,
                host_class: None,
                key_authority_kind: None,
            })
            .collect(),
        measurement_profile_root: [12u8; 32],
        policy_hash: [13u8; 32],
        transparency_log_id: "guardian-test".into(),
    };
    let decision = GuardianDecision {
        domain: GuardianDecisionDomain::ConsensusSlot as u8,
        subject: manifest.validator_account_id.0.to_vec(),
        payload_hash: [99u8; 32],
        counter: 1,
        trace_hash: [77u8; 32],
        measurement_root: manifest.measurement_profile_root,
        policy_hash: manifest.policy_hash,
    };
    let err = sign_decision_with_members(
        &manifest,
        &decision,
        decision.counter,
        decision.trace_hash,
        &[
            (0, member_keys[0].private_key()),
            (0, member_keys[0].private_key()),
        ],
    )
    .unwrap_err();
    assert!(err.to_string().contains("duplicate signer index"));
}

#[test]
fn experimental_nested_guardian_requires_witness_certificate() {
    let (mut engine, header, manifest, preimage, _, _) = build_case(&[(0, 0), (1, 1)]);
    engine.safety_mode = AftSafetyMode::ExperimentalNestedGuardian;
    let witness_members = vec![
        BlsKeyPair::generate().unwrap(),
        BlsKeyPair::generate().unwrap(),
        BlsKeyPair::generate().unwrap(),
    ];
    let witness_manifest = build_witness_manifest(&witness_members);
    let err = engine
        .verify_experimental_witness_certificate_against_manifest(
            &header,
            header.guardian_certificate.as_ref().unwrap(),
            &witness_manifest,
        )
        .unwrap_err();
    assert!(matches!(err, ConsensusError::BlockVerificationFailed(_)));
    engine
        .verify_guardianized_certificate_against_manifest(&header, &preimage, &manifest)
        .unwrap();
}

#[test]
fn experimental_nested_guardian_verifies_witness_certificate() {
    let (mut engine, mut header, manifest, preimage, _, _) = build_case(&[(0, 0), (1, 1)]);
    engine.safety_mode = AftSafetyMode::ExperimentalNestedGuardian;
    let witness_members = vec![
        BlsKeyPair::generate().unwrap(),
        BlsKeyPair::generate().unwrap(),
        BlsKeyPair::generate().unwrap(),
    ];
    let witness_manifest = build_witness_manifest(&witness_members);
    let guardian_certificate = header.guardian_certificate.as_ref().unwrap().clone();
    let statement = engine.experimental_witness_statement(&header, &guardian_certificate);
    let witness_certificate = sign_witness_statement_with_members(
        &witness_manifest,
        &statement,
        &[
            (0, witness_members[0].private_key()),
            (2, witness_members[2].private_key()),
        ],
    )
    .unwrap();
    header
        .guardian_certificate
        .as_mut()
        .unwrap()
        .experimental_witness_certificate = Some(witness_certificate);

    engine
        .verify_guardianized_certificate_against_manifest(&header, &preimage, &manifest)
        .unwrap();
    engine
        .verify_experimental_witness_certificate_against_manifest(
            &header,
            header.guardian_certificate.as_ref().unwrap(),
            &witness_manifest,
        )
        .unwrap();
}

#[test]
fn experimental_nested_guardian_rejects_tampered_recovery_binding() {
    let (mut engine, mut header, manifest, preimage, _, _) = build_case(&[(0, 0), (1, 1)]);
    engine.safety_mode = AftSafetyMode::ExperimentalNestedGuardian;
    let witness_members = vec![
        BlsKeyPair::generate().unwrap(),
        BlsKeyPair::generate().unwrap(),
        BlsKeyPair::generate().unwrap(),
    ];
    let witness_manifest = build_witness_manifest(&witness_members);
    let guardian_certificate = header.guardian_certificate.as_ref().unwrap().clone();
    let mut statement = engine.experimental_witness_statement(&header, &guardian_certificate);
    statement.recovery_binding = Some(GuardianWitnessRecoveryBinding {
        recovery_capsule_hash: [61u8; 32],
        share_commitment_hash: [62u8; 32],
    });
    let mut witness_certificate = sign_witness_statement_with_members(
        &witness_manifest,
        &statement,
        &[
            (0, witness_members[0].private_key()),
            (2, witness_members[2].private_key()),
        ],
    )
    .unwrap();
    witness_certificate.recovery_binding = Some(GuardianWitnessRecoveryBinding {
        recovery_capsule_hash: [63u8; 32],
        share_commitment_hash: [64u8; 32],
    });
    header
        .guardian_certificate
        .as_mut()
        .unwrap()
        .experimental_witness_certificate = Some(witness_certificate);

    engine
        .verify_guardianized_certificate_against_manifest(&header, &preimage, &manifest)
        .unwrap();
    let err = engine
        .verify_experimental_witness_certificate_against_manifest(
            &header,
            header.guardian_certificate.as_ref().unwrap(),
            &witness_manifest,
        )
        .unwrap_err();
    assert!(matches!(err, ConsensusError::BlockVerificationFailed(_)));
}

#[tokio::test]
async fn experimental_nested_guardian_rejects_unassigned_witness_certificate() {
    let (mut engine, mut header, manifest, preimage, _, guardian_log_keypair) =
        build_case(&[(0, 0), (1, 1)]);
    engine.safety_mode = AftSafetyMode::ExperimentalNestedGuardian;
    let guardian_log_descriptor =
        build_log_descriptor(&manifest.transparency_log_id, &guardian_log_keypair);
    let witness_log_keypair = Keypair::generate_ed25519();

    let witness_members_a = vec![
        BlsKeyPair::generate().unwrap(),
        BlsKeyPair::generate().unwrap(),
        BlsKeyPair::generate().unwrap(),
        BlsKeyPair::generate().unwrap(),
    ];
    let witness_members_b = vec![
        BlsKeyPair::generate().unwrap(),
        BlsKeyPair::generate().unwrap(),
        BlsKeyPair::generate().unwrap(),
        BlsKeyPair::generate().unwrap(),
    ];
    let witness_manifest_a = build_witness_manifest(&witness_members_a);
    let mut witness_manifest_b = build_witness_manifest(&witness_members_b);
    witness_manifest_b.committee_id = "witness-b".into();
    witness_manifest_b.stratum_id = "stratum-b".into();

    let witness_hash_a = canonical_witness_manifest_hash(&witness_manifest_a).unwrap();
    let witness_hash_b = canonical_witness_manifest_hash(&witness_manifest_b).unwrap();
    let witness_set = GuardianWitnessSet {
        epoch: witness_manifest_a.epoch,
        manifest_hashes: vec![witness_hash_a, witness_hash_b],
        checkpoint_interval_blocks: 1,
    };
    let witness_seed = GuardianWitnessEpochSeed {
        epoch: witness_manifest_a.epoch,
        seed: [88u8; 32],
        checkpoint_interval_blocks: 1,
        max_reassignment_depth: 1,
    };
    let expected_assignment = derive_guardian_witness_assignment(
        &witness_seed,
        &witness_set,
        header.producer_account_id,
        header.height,
        header.view,
        0,
    )
    .unwrap();
    let wrong_manifest = if expected_assignment.manifest_hash == witness_hash_a {
        &witness_manifest_b
    } else {
        &witness_manifest_a
    };
    let wrong_members = if expected_assignment.manifest_hash == witness_hash_a {
        &witness_members_b
    } else {
        &witness_members_a
    };
    let statement = engine
        .experimental_witness_statement(&header, header.guardian_certificate.as_ref().unwrap());
    let mut witness_certificate = sign_witness_statement_with_members(
        wrong_manifest,
        &statement,
        &[
            (0, wrong_members[0].private_key()),
            (1, wrong_members[1].private_key()),
            (2, wrong_members[2].private_key()),
        ],
    )
    .unwrap();
    let witness_checkpoint_entry =
        codec::to_bytes_canonical(&(statement.clone(), witness_certificate.clone())).unwrap();
    witness_certificate.log_checkpoint = Some(build_signed_checkpoint(
        &wrong_manifest.transparency_log_id,
        &witness_log_keypair,
        &[witness_checkpoint_entry],
        0,
        1,
    ));
    header
        .guardian_certificate
        .as_mut()
        .unwrap()
        .experimental_witness_certificate = Some(witness_certificate);

    let parent_view = build_parent_view(
        &manifest,
        &[
            guardian_log_descriptor,
            build_log_descriptor(
                &witness_manifest_a.transparency_log_id,
                &witness_log_keypair,
            ),
            build_log_descriptor(
                &witness_manifest_b.transparency_log_id,
                &witness_log_keypair,
            ),
        ],
        &[witness_manifest_a, witness_manifest_b],
        witness_set,
        witness_seed,
        &[header
            .guardian_certificate
            .as_ref()
            .unwrap()
            .log_checkpoint
            .as_ref()
            .unwrap()
            .clone()],
    );
    let err = engine
        .verify_guardianized_certificate(&header, &preimage, &parent_view)
        .await
        .unwrap_err();
    assert!(matches!(err, ConsensusError::BlockVerificationFailed(_)));
}

#[tokio::test]
async fn experimental_nested_guardian_accepts_deterministically_assigned_witness_certificate() {
    let (mut engine, mut header, manifest, preimage, _, guardian_log_keypair) =
        build_case(&[(0, 0), (1, 1)]);
    engine.safety_mode = AftSafetyMode::ExperimentalNestedGuardian;
    let guardian_log_descriptor =
        build_log_descriptor(&manifest.transparency_log_id, &guardian_log_keypair);
    let witness_log_keypair = Keypair::generate_ed25519();

    let witness_members_a = vec![
        BlsKeyPair::generate().unwrap(),
        BlsKeyPair::generate().unwrap(),
        BlsKeyPair::generate().unwrap(),
        BlsKeyPair::generate().unwrap(),
    ];
    let witness_members_b = vec![
        BlsKeyPair::generate().unwrap(),
        BlsKeyPair::generate().unwrap(),
        BlsKeyPair::generate().unwrap(),
        BlsKeyPair::generate().unwrap(),
    ];
    let witness_manifest_a = build_witness_manifest(&witness_members_a);
    let mut witness_manifest_b = build_witness_manifest(&witness_members_b);
    witness_manifest_b.committee_id = "witness-b".into();
    witness_manifest_b.stratum_id = "stratum-b".into();

    let witness_hash_a = canonical_witness_manifest_hash(&witness_manifest_a).unwrap();
    let witness_hash_b = canonical_witness_manifest_hash(&witness_manifest_b).unwrap();
    let witness_set = GuardianWitnessSet {
        epoch: witness_manifest_a.epoch,
        manifest_hashes: vec![witness_hash_a, witness_hash_b],
        checkpoint_interval_blocks: 1,
    };
    let witness_seed = GuardianWitnessEpochSeed {
        epoch: witness_manifest_a.epoch,
        seed: [99u8; 32],
        checkpoint_interval_blocks: 1,
        max_reassignment_depth: 1,
    };
    let expected_assignment = derive_guardian_witness_assignment(
        &witness_seed,
        &witness_set,
        header.producer_account_id,
        header.height,
        header.view,
        0,
    )
    .unwrap();
    let (assigned_manifest, assigned_members) =
        if expected_assignment.manifest_hash == witness_hash_a {
            (&witness_manifest_a, &witness_members_a)
        } else {
            (&witness_manifest_b, &witness_members_b)
        };
    let statement = engine
        .experimental_witness_statement(&header, header.guardian_certificate.as_ref().unwrap());
    let mut witness_certificate = sign_witness_statement_with_members(
        assigned_manifest,
        &statement,
        &[
            (0, assigned_members[0].private_key()),
            (1, assigned_members[1].private_key()),
            (2, assigned_members[2].private_key()),
        ],
    )
    .unwrap();
    let witness_checkpoint_entry =
        codec::to_bytes_canonical(&(statement.clone(), witness_certificate.clone())).unwrap();
    witness_certificate.log_checkpoint = Some(build_signed_checkpoint(
        &assigned_manifest.transparency_log_id,
        &witness_log_keypair,
        &[witness_checkpoint_entry],
        0,
        1,
    ));
    header
        .guardian_certificate
        .as_mut()
        .unwrap()
        .experimental_witness_certificate = Some(witness_certificate);

    let parent_view = build_parent_view(
        &manifest,
        &[
            guardian_log_descriptor,
            build_log_descriptor(
                &witness_manifest_a.transparency_log_id,
                &witness_log_keypair,
            ),
            build_log_descriptor(
                &witness_manifest_b.transparency_log_id,
                &witness_log_keypair,
            ),
        ],
        &[witness_manifest_a, witness_manifest_b],
        witness_set,
        witness_seed,
        &[
            header
                .guardian_certificate
                .as_ref()
                .unwrap()
                .log_checkpoint
                .as_ref()
                .unwrap()
                .clone(),
            header
                .guardian_certificate
                .as_ref()
                .unwrap()
                .experimental_witness_certificate
                .as_ref()
                .unwrap()
                .log_checkpoint
                .as_ref()
                .unwrap()
                .clone(),
        ],
    );
    engine
        .verify_guardianized_certificate(&header, &preimage, &parent_view)
        .await
        .unwrap();
}

#[tokio::test]
async fn asymptote_accepts_valid_sealed_finality_proof() {
    let (mut engine, mut header, manifest, preimage, _, guardian_log_keypair) =
        build_case(&[(0, 0), (1, 1)]);
    engine.safety_mode = AftSafetyMode::Asymptote;
    let guardian_log_descriptor =
        build_log_descriptor(&manifest.transparency_log_id, &guardian_log_keypair);
    let witness_log_keypair = Keypair::generate_ed25519();

    let witness_members_a = vec![
        BlsKeyPair::generate().unwrap(),
        BlsKeyPair::generate().unwrap(),
        BlsKeyPair::generate().unwrap(),
        BlsKeyPair::generate().unwrap(),
    ];
    let witness_members_b = vec![
        BlsKeyPair::generate().unwrap(),
        BlsKeyPair::generate().unwrap(),
        BlsKeyPair::generate().unwrap(),
        BlsKeyPair::generate().unwrap(),
    ];
    let witness_manifest_a = build_witness_manifest(&witness_members_a);
    let mut witness_manifest_b = build_witness_manifest(&witness_members_b);
    witness_manifest_b.committee_id = "witness-b".into();
    witness_manifest_b.stratum_id = "stratum-b".into();
    witness_manifest_b.transparency_log_id = "witness-test-b".into();

    let witness_hash_a = canonical_witness_manifest_hash(&witness_manifest_a).unwrap();
    let witness_hash_b = canonical_witness_manifest_hash(&witness_manifest_b).unwrap();
    let witness_set = GuardianWitnessSet {
        epoch: witness_manifest_a.epoch,
        manifest_hashes: vec![witness_hash_a, witness_hash_b],
        checkpoint_interval_blocks: 1,
    };
    let witness_seed = GuardianWitnessEpochSeed {
        epoch: witness_manifest_a.epoch,
        seed: [77u8; 32],
        checkpoint_interval_blocks: 1,
        max_reassignment_depth: 0,
    };
    let assignments = derive_guardian_witness_assignments(
        &witness_seed,
        &witness_set,
        header.producer_account_id,
        header.height,
        header.view,
        0,
        2,
    )
    .unwrap();
    let statement = engine
        .experimental_witness_statement(&header, header.guardian_certificate.as_ref().unwrap());
    let mut witness_certificates = Vec::new();
    let mut anchored_checkpoints = vec![header
        .guardian_certificate
        .as_ref()
        .unwrap()
        .log_checkpoint
        .as_ref()
        .unwrap()
        .clone()];
    for assignment in assignments {
        let (assigned_manifest, assigned_members) = if assignment.manifest_hash == witness_hash_a {
            (&witness_manifest_a, &witness_members_a)
        } else {
            (&witness_manifest_b, &witness_members_b)
        };
        let mut witness_certificate = sign_witness_statement_with_members(
            assigned_manifest,
            &statement,
            &[
                (0, assigned_members[0].private_key()),
                (1, assigned_members[1].private_key()),
                (2, assigned_members[2].private_key()),
            ],
        )
        .unwrap();
        let witness_checkpoint_entry =
            codec::to_bytes_canonical(&(statement.clone(), witness_certificate.clone())).unwrap();
        witness_certificate.log_checkpoint = Some(build_signed_checkpoint(
            &assigned_manifest.transparency_log_id,
            &witness_log_keypair,
            std::slice::from_ref(&witness_checkpoint_entry),
            0,
            1,
        ));
        anchored_checkpoints.push(witness_certificate.log_checkpoint.clone().unwrap());
        witness_certificates.push(witness_certificate);
    }
    header.sealed_finality_proof = Some(SealedFinalityProof {
        epoch: manifest.epoch,
        finality_tier: FinalityTier::SealedFinal,
        collapse_state: CollapseState::SealedFinal,
        guardian_manifest_hash: header.guardian_certificate.as_ref().unwrap().manifest_hash,
        guardian_decision_hash: header.guardian_certificate.as_ref().unwrap().decision_hash,
        guardian_counter: header.oracle_counter,
        guardian_trace_hash: header.oracle_trace_hash,
        guardian_measurement_root: header
            .guardian_certificate
            .as_ref()
            .unwrap()
            .measurement_root,
        policy_hash: manifest.policy_hash,
        witness_certificates,
        observer_certificates: Vec::new(),
        observer_close_certificate: None,
        observer_transcripts: Vec::new(),
        observer_challenges: Vec::new(),
        observer_transcript_commitment: None,
        observer_challenge_commitment: None,
        observer_canonical_close: None,
        observer_canonical_abort: None,
        veto_proofs: Vec::new(),
        divergence_signals: Vec::new(),
        proof_signature: SignatureProof::default(),
    });
    sign_test_sealed_finality_proof(
        header.sealed_finality_proof.as_mut().unwrap(),
        &guardian_log_keypair,
    );

    let parent_view = build_parent_view_with_asymptote_policy(
        &manifest,
        &[
            guardian_log_descriptor,
            build_log_descriptor(
                &witness_manifest_a.transparency_log_id,
                &witness_log_keypair,
            ),
            build_log_descriptor(
                &witness_manifest_b.transparency_log_id,
                &witness_log_keypair,
            ),
        ],
        &[witness_manifest_a, witness_manifest_b],
        witness_set,
        witness_seed,
        &anchored_checkpoints,
        AsymptotePolicy {
            epoch: manifest.epoch,
            high_risk_effect_tier: FinalityTier::SealedFinal,
            required_witness_strata: vec!["stratum-a".into(), "stratum-b".into()],
            escalation_witness_strata: vec![
                "stratum-a".into(),
                "stratum-b".into(),
                "stratum-c".into(),
            ],
            observer_rounds: 0,
            observer_committee_size: 0,
            observer_correlation_budget: AsymptoteObserverCorrelationBudget::default(),
            observer_sealing_mode: AsymptoteObserverSealingMode::SampledCloseV1,
            observer_challenge_window_ms: 0,
            max_reassignment_depth: 0,
            max_checkpoint_staleness_ms: 120_000,
        },
    );

    engine
        .verify_guardianized_certificate(&header, &preimage, &parent_view)
        .await
        .unwrap();
}

#[tokio::test]
async fn asymptote_accepts_sealed_finality_proof_with_distinct_recovery_bindings() {
    let (mut engine, mut header, manifest, preimage, _, guardian_log_keypair) =
        build_case(&[(0, 0), (1, 1)]);
    engine.safety_mode = AftSafetyMode::Asymptote;
    let guardian_log_descriptor =
        build_log_descriptor(&manifest.transparency_log_id, &guardian_log_keypair);
    let witness_log_keypair = Keypair::generate_ed25519();

    let witness_members_a = vec![
        BlsKeyPair::generate().unwrap(),
        BlsKeyPair::generate().unwrap(),
        BlsKeyPair::generate().unwrap(),
        BlsKeyPair::generate().unwrap(),
    ];
    let witness_members_b = vec![
        BlsKeyPair::generate().unwrap(),
        BlsKeyPair::generate().unwrap(),
        BlsKeyPair::generate().unwrap(),
        BlsKeyPair::generate().unwrap(),
    ];
    let witness_manifest_a = build_witness_manifest(&witness_members_a);
    let mut witness_manifest_b = build_witness_manifest(&witness_members_b);
    witness_manifest_b.committee_id = "witness-b".into();
    witness_manifest_b.stratum_id = "stratum-b".into();
    witness_manifest_b.transparency_log_id = "witness-test-b".into();

    let witness_hash_a = canonical_witness_manifest_hash(&witness_manifest_a).unwrap();
    let witness_hash_b = canonical_witness_manifest_hash(&witness_manifest_b).unwrap();
    let witness_set = GuardianWitnessSet {
        epoch: witness_manifest_a.epoch,
        manifest_hashes: vec![witness_hash_a, witness_hash_b],
        checkpoint_interval_blocks: 1,
    };
    let witness_seed = GuardianWitnessEpochSeed {
        epoch: witness_manifest_a.epoch,
        seed: [79u8; 32],
        checkpoint_interval_blocks: 1,
        max_reassignment_depth: 0,
    };
    let assignments = derive_guardian_witness_assignments(
        &witness_seed,
        &witness_set,
        header.producer_account_id,
        header.height,
        header.view,
        0,
        2,
    )
    .unwrap();
    let recovery_capsule_hash = [0x91u8; 32];
    let mut witness_certificates = Vec::new();
    let mut anchored_checkpoints = vec![header
        .guardian_certificate
        .as_ref()
        .unwrap()
        .log_checkpoint
        .as_ref()
        .unwrap()
        .clone()];
    for (index, assignment) in assignments.into_iter().enumerate() {
        let (assigned_manifest, assigned_members) = if assignment.manifest_hash == witness_hash_a {
            (&witness_manifest_a, &witness_members_a)
        } else {
            (&witness_manifest_b, &witness_members_b)
        };
        let recovery_binding = GuardianWitnessRecoveryBinding {
            recovery_capsule_hash,
            share_commitment_hash: [0xA0u8.saturating_add(index as u8); 32],
        };
        let statement = ioi_types::app::guardian_witness_statement_for_header_with_recovery_binding(
            &header,
            header.guardian_certificate.as_ref().unwrap(),
            Some(recovery_binding.clone()),
        );
        let mut witness_certificate = sign_witness_statement_with_members(
            assigned_manifest,
            &statement,
            &[
                (0, assigned_members[0].private_key()),
                (1, assigned_members[1].private_key()),
                (2, assigned_members[2].private_key()),
            ],
        )
        .unwrap();
        let witness_checkpoint_entry =
            codec::to_bytes_canonical(&(statement.clone(), witness_certificate.clone())).unwrap();
        witness_certificate.log_checkpoint = Some(build_signed_checkpoint(
            &assigned_manifest.transparency_log_id,
            &witness_log_keypair,
            std::slice::from_ref(&witness_checkpoint_entry),
            0,
            1,
        ));
        anchored_checkpoints.push(witness_certificate.log_checkpoint.clone().unwrap());
        witness_certificates.push(witness_certificate);
    }
    header.sealed_finality_proof = Some(SealedFinalityProof {
        epoch: manifest.epoch,
        finality_tier: FinalityTier::SealedFinal,
        collapse_state: CollapseState::SealedFinal,
        guardian_manifest_hash: header.guardian_certificate.as_ref().unwrap().manifest_hash,
        guardian_decision_hash: header.guardian_certificate.as_ref().unwrap().decision_hash,
        guardian_counter: header.oracle_counter,
        guardian_trace_hash: header.oracle_trace_hash,
        guardian_measurement_root: header
            .guardian_certificate
            .as_ref()
            .unwrap()
            .measurement_root,
        policy_hash: manifest.policy_hash,
        witness_certificates,
        observer_certificates: Vec::new(),
        observer_close_certificate: None,
        observer_transcripts: Vec::new(),
        observer_challenges: Vec::new(),
        observer_transcript_commitment: None,
        observer_challenge_commitment: None,
        observer_canonical_close: None,
        observer_canonical_abort: None,
        veto_proofs: Vec::new(),
        divergence_signals: Vec::new(),
        proof_signature: SignatureProof::default(),
    });
    sign_test_sealed_finality_proof(
        header.sealed_finality_proof.as_mut().unwrap(),
        &guardian_log_keypair,
    );

    let parent_view = build_parent_view_with_asymptote_policy(
        &manifest,
        &[
            guardian_log_descriptor,
            build_log_descriptor(
                &witness_manifest_a.transparency_log_id,
                &witness_log_keypair,
            ),
            build_log_descriptor(
                &witness_manifest_b.transparency_log_id,
                &witness_log_keypair,
            ),
        ],
        &[witness_manifest_a, witness_manifest_b],
        witness_set,
        witness_seed,
        &anchored_checkpoints,
        AsymptotePolicy {
            epoch: manifest.epoch,
            high_risk_effect_tier: FinalityTier::SealedFinal,
            required_witness_strata: vec!["stratum-a".into(), "stratum-b".into()],
            escalation_witness_strata: vec![
                "stratum-a".into(),
                "stratum-b".into(),
                "stratum-c".into(),
            ],
            observer_rounds: 0,
            observer_committee_size: 0,
            observer_correlation_budget: AsymptoteObserverCorrelationBudget::default(),
            observer_sealing_mode: AsymptoteObserverSealingMode::SampledCloseV1,
            observer_challenge_window_ms: 0,
            max_reassignment_depth: 0,
            max_checkpoint_staleness_ms: 120_000,
        },
    );

    engine
        .verify_guardianized_certificate(&header, &preimage, &parent_view)
        .await
        .unwrap();
}

#[tokio::test]
async fn asymptote_rejects_duplicate_witness_committees_in_sealed_finality_proof() {
    let (mut engine, mut header, manifest, preimage, _, guardian_log_keypair) =
        build_case(&[(0, 0), (1, 1)]);
    engine.safety_mode = AftSafetyMode::Asymptote;
    let guardian_log_descriptor =
        build_log_descriptor(&manifest.transparency_log_id, &guardian_log_keypair);
    let witness_log_keypair = Keypair::generate_ed25519();

    let witness_members_a = vec![
        BlsKeyPair::generate().unwrap(),
        BlsKeyPair::generate().unwrap(),
        BlsKeyPair::generate().unwrap(),
        BlsKeyPair::generate().unwrap(),
    ];
    let witness_members_b = vec![
        BlsKeyPair::generate().unwrap(),
        BlsKeyPair::generate().unwrap(),
        BlsKeyPair::generate().unwrap(),
        BlsKeyPair::generate().unwrap(),
    ];
    let witness_manifest_a = build_witness_manifest(&witness_members_a);
    let mut witness_manifest_b = build_witness_manifest(&witness_members_b);
    witness_manifest_b.committee_id = "witness-b".into();
    witness_manifest_b.stratum_id = "stratum-b".into();
    witness_manifest_b.transparency_log_id = "witness-test-b".into();

    let witness_hash_a = canonical_witness_manifest_hash(&witness_manifest_a).unwrap();
    let witness_hash_b = canonical_witness_manifest_hash(&witness_manifest_b).unwrap();
    let witness_set = GuardianWitnessSet {
        epoch: witness_manifest_a.epoch,
        manifest_hashes: vec![witness_hash_a, witness_hash_b],
        checkpoint_interval_blocks: 1,
    };
    let witness_seed = GuardianWitnessEpochSeed {
        epoch: witness_manifest_a.epoch,
        seed: [88u8; 32],
        checkpoint_interval_blocks: 1,
        max_reassignment_depth: 0,
    };
    let assignments = derive_guardian_witness_assignments(
        &witness_seed,
        &witness_set,
        header.producer_account_id,
        header.height,
        header.view,
        0,
        2,
    )
    .unwrap();
    let statement = engine
        .experimental_witness_statement(&header, header.guardian_certificate.as_ref().unwrap());
    let first_assignment = assignments.first().unwrap();
    let (assigned_manifest, assigned_members) = if first_assignment.manifest_hash == witness_hash_a
    {
        (&witness_manifest_a, &witness_members_a)
    } else {
        (&witness_manifest_b, &witness_members_b)
    };
    let mut witness_certificate = sign_witness_statement_with_members(
        assigned_manifest,
        &statement,
        &[
            (0, assigned_members[0].private_key()),
            (1, assigned_members[1].private_key()),
            (2, assigned_members[2].private_key()),
        ],
    )
    .unwrap();
    let witness_checkpoint_entry =
        codec::to_bytes_canonical(&(statement.clone(), witness_certificate.clone())).unwrap();
    witness_certificate.log_checkpoint = Some(build_signed_checkpoint(
        &assigned_manifest.transparency_log_id,
        &witness_log_keypair,
        std::slice::from_ref(&witness_checkpoint_entry),
        0,
        1,
    ));
    let anchored_checkpoints = vec![
        header
            .guardian_certificate
            .as_ref()
            .unwrap()
            .log_checkpoint
            .as_ref()
            .unwrap()
            .clone(),
        witness_certificate.log_checkpoint.clone().unwrap(),
    ];
    header.sealed_finality_proof = Some(SealedFinalityProof {
        epoch: manifest.epoch,
        finality_tier: FinalityTier::SealedFinal,
        collapse_state: CollapseState::SealedFinal,
        guardian_manifest_hash: header.guardian_certificate.as_ref().unwrap().manifest_hash,
        guardian_decision_hash: header.guardian_certificate.as_ref().unwrap().decision_hash,
        guardian_counter: header.oracle_counter,
        guardian_trace_hash: header.oracle_trace_hash,
        guardian_measurement_root: header
            .guardian_certificate
            .as_ref()
            .unwrap()
            .measurement_root,
        policy_hash: manifest.policy_hash,
        witness_certificates: vec![witness_certificate.clone(), witness_certificate],
        observer_certificates: Vec::new(),
        observer_close_certificate: None,
        observer_transcripts: Vec::new(),
        observer_challenges: Vec::new(),
        observer_transcript_commitment: None,
        observer_challenge_commitment: None,
        observer_canonical_close: None,
        observer_canonical_abort: None,
        veto_proofs: Vec::new(),
        divergence_signals: Vec::new(),
        proof_signature: SignatureProof::default(),
    });
    sign_test_sealed_finality_proof(
        header.sealed_finality_proof.as_mut().unwrap(),
        &guardian_log_keypair,
    );
    let parent_view = build_parent_view_with_asymptote_policy(
        &manifest,
        &[
            guardian_log_descriptor,
            build_log_descriptor(
                &witness_manifest_a.transparency_log_id,
                &witness_log_keypair,
            ),
            build_log_descriptor(
                &witness_manifest_b.transparency_log_id,
                &witness_log_keypair,
            ),
        ],
        &[witness_manifest_a, witness_manifest_b],
        witness_set,
        witness_seed,
        &anchored_checkpoints,
        AsymptotePolicy {
            epoch: manifest.epoch,
            high_risk_effect_tier: FinalityTier::SealedFinal,
            required_witness_strata: vec!["stratum-a".into(), "stratum-b".into()],
            escalation_witness_strata: vec![
                "stratum-a".into(),
                "stratum-b".into(),
                "stratum-c".into(),
            ],
            observer_rounds: 0,
            observer_committee_size: 0,
            observer_correlation_budget: AsymptoteObserverCorrelationBudget::default(),
            observer_sealing_mode: AsymptoteObserverSealingMode::SampledCloseV1,
            observer_challenge_window_ms: 0,
            max_reassignment_depth: 0,
            max_checkpoint_staleness_ms: 120_000,
        },
    );

    let err = engine
        .verify_guardianized_certificate(&header, &preimage, &parent_view)
        .await
        .unwrap_err();
    assert!(matches!(err, ConsensusError::BlockVerificationFailed(_)));
}

#[tokio::test]
async fn asymptote_accepts_equal_authority_observer_sealed_finality_proof() {
    let (mut engine, mut header, manifest, preimage, _, guardian_log_keypair) =
        build_case(&[(0, 0), (1, 1)]);
    engine.safety_mode = AftSafetyMode::Asymptote;
    let guardian_log_descriptor =
        build_log_descriptor(&manifest.transparency_log_id, &guardian_log_keypair);
    let witness_seed = GuardianWitnessEpochSeed {
        epoch: manifest.epoch,
        seed: [91u8; 32],
        checkpoint_interval_blocks: 1,
        max_reassignment_depth: 0,
    };
    let policy = AsymptotePolicy {
        epoch: manifest.epoch,
        high_risk_effect_tier: FinalityTier::SealedFinal,
        required_witness_strata: Vec::new(),
        escalation_witness_strata: Vec::new(),
        observer_rounds: 2,
        observer_committee_size: 1,
        observer_correlation_budget: AsymptoteObserverCorrelationBudget::default(),
        observer_sealing_mode: AsymptoteObserverSealingMode::SampledCloseV1,
        observer_challenge_window_ms: 0,
        max_reassignment_depth: 0,
        max_checkpoint_staleness_ms: 120_000,
    };
    let validators = vec![
        header.producer_account_id,
        AccountId([31u8; 32]),
        AccountId([32u8; 32]),
        AccountId([33u8; 32]),
    ];
    let observer_assignments = derive_asymptote_observer_assignments(
        &witness_seed,
        &build_validator_sets(validators.clone()).current,
        header.producer_account_id,
        header.height,
        header.view,
        policy.observer_rounds,
        policy.observer_committee_size,
    )
    .unwrap();
    let observer_assignments_hash =
        canonical_asymptote_observer_assignments_hash(&observer_assignments).unwrap();

    let observer_log_keypair = Keypair::generate_ed25519();
    let mut observer_manifests = Vec::new();
    let mut observer_descriptors = vec![guardian_log_descriptor];
    let mut anchored_checkpoints = vec![header
        .guardian_certificate
        .as_ref()
        .unwrap()
        .log_checkpoint
        .as_ref()
        .unwrap()
        .clone()];
    let mut observer_certificates = Vec::new();
    let base_certificate = header.guardian_certificate.as_ref().unwrap().clone();
    let selected_accounts = observer_assignments
        .iter()
        .map(|assignment| assignment.observer_account_id)
        .collect::<std::collections::HashSet<_>>();
    let mut selected_manifests = HashMap::new();
    for account in validators
        .iter()
        .copied()
        .filter(|account| *account != header.producer_account_id)
    {
        let member_keys = vec![
            BlsKeyPair::generate().unwrap(),
            BlsKeyPair::generate().unwrap(),
            BlsKeyPair::generate().unwrap(),
        ];
        let log_id = format!("observer-{}", hex::encode(account.as_ref()));
        let observer_manifest =
            build_observer_manifest(account, manifest.epoch, [61u8; 32], &log_id, &member_keys);
        if selected_accounts.contains(&account) {
            selected_manifests.insert(account, (observer_manifest.clone(), member_keys));
        }
        observer_manifests.push(observer_manifest);
    }
    for assignment in observer_assignments {
        let (observer_manifest, member_keys) = selected_manifests
            .remove(&assignment.observer_account_id)
            .unwrap();
        let provisional = AsymptoteObserverCertificate {
            assignment: assignment.clone(),
            verdict: AsymptoteObserverVerdict::Ok,
            veto_kind: None,
            evidence_hash: [0u8; 32],
            guardian_certificate: GuardianQuorumCertificate::default(),
        };
        let statement = engine
            .asymptote_observer_statement(&header, &base_certificate, &provisional)
            .unwrap();
        let decision = GuardianDecision {
            domain: GuardianDecisionDomain::AsymptoteObserve as u8,
            subject: assignment.observer_account_id.0.to_vec(),
            payload_hash: ioi_crypto::algorithms::hash::sha256(
                &codec::to_bytes_canonical(&statement).unwrap(),
            )
            .unwrap(),
            counter: u64::from(assignment.round) + 1,
            trace_hash: [assignment.round as u8 + 1; 32],
            measurement_root: observer_manifest.measurement_profile_root,
            policy_hash: observer_manifest.policy_hash,
        };
        let mut observer_guardian_certificate = sign_decision_with_members(
            &observer_manifest,
            &decision,
            decision.counter,
            decision.trace_hash,
            &[
                (0, member_keys[0].private_key()),
                (1, member_keys[1].private_key()),
            ],
        )
        .unwrap();
        let checkpoint_entry =
            codec::to_bytes_canonical(&(decision.clone(), observer_guardian_certificate.clone()))
                .unwrap();
        observer_guardian_certificate.log_checkpoint = Some(build_signed_checkpoint(
            &observer_manifest.transparency_log_id,
            &observer_log_keypair,
            &[checkpoint_entry],
            0,
            u64::from(assignment.round) + 1,
        ));
        anchored_checkpoints.push(
            observer_guardian_certificate
                .log_checkpoint
                .as_ref()
                .unwrap()
                .clone(),
        );
        observer_descriptors.push(build_log_descriptor(
            &observer_manifest.transparency_log_id,
            &observer_log_keypair,
        ));
        observer_certificates.push(AsymptoteObserverCertificate {
            assignment,
            verdict: AsymptoteObserverVerdict::Ok,
            veto_kind: None,
            evidence_hash: [0u8; 32],
            guardian_certificate: observer_guardian_certificate,
        });
    }

    header.sealed_finality_proof = Some(SealedFinalityProof {
        epoch: manifest.epoch,
        finality_tier: FinalityTier::SealedFinal,
        collapse_state: CollapseState::SealedFinal,
        guardian_manifest_hash: base_certificate.manifest_hash,
        guardian_decision_hash: base_certificate.decision_hash,
        guardian_counter: base_certificate.counter,
        guardian_trace_hash: base_certificate.trace_hash,
        guardian_measurement_root: base_certificate.measurement_root,
        policy_hash: manifest.policy_hash,
        witness_certificates: Vec::new(),
        observer_certificates,
        observer_close_certificate: Some(AsymptoteObserverCloseCertificate {
            epoch: manifest.epoch,
            height: header.height,
            view: header.view,
            assignments_hash: observer_assignments_hash,
            expected_assignments: 2,
            ok_count: 2,
            veto_count: 0,
        }),
        observer_transcripts: Vec::new(),
        observer_challenges: Vec::new(),
        observer_transcript_commitment: None,
        observer_challenge_commitment: None,
        observer_canonical_close: None,
        observer_canonical_abort: None,
        veto_proofs: Vec::new(),
        divergence_signals: Vec::new(),
        proof_signature: SignatureProof::default(),
    });
    sign_test_sealed_finality_proof(
        header.sealed_finality_proof.as_mut().unwrap(),
        &guardian_log_keypair,
    );

    let parent_view = build_parent_view_with_asymptote_observers(
        &manifest,
        &observer_descriptors,
        policy,
        witness_seed,
        &anchored_checkpoints,
        validators,
        &observer_manifests,
    );

    engine
        .verify_guardianized_certificate(&header, &preimage, &parent_view)
        .await
        .unwrap();
}

#[tokio::test]
async fn asymptote_accepts_canonical_observer_sealed_finality_proof() {
    let (mut engine, mut header, manifest, preimage, _, guardian_log_keypair) =
        build_case(&[(0, 0), (1, 1)]);
    engine.safety_mode = AftSafetyMode::Asymptote;
    let guardian_log_descriptor =
        build_log_descriptor(&manifest.transparency_log_id, &guardian_log_keypair);
    let witness_seed = GuardianWitnessEpochSeed {
        epoch: manifest.epoch,
        seed: [101u8; 32],
        checkpoint_interval_blocks: 1,
        max_reassignment_depth: 0,
    };
    let policy = AsymptotePolicy {
        epoch: manifest.epoch,
        high_risk_effect_tier: FinalityTier::SealedFinal,
        required_witness_strata: Vec::new(),
        escalation_witness_strata: Vec::new(),
        observer_rounds: 2,
        observer_committee_size: 1,
        observer_correlation_budget: AsymptoteObserverCorrelationBudget::default(),
        observer_sealing_mode: AsymptoteObserverSealingMode::CanonicalChallengeV1,
        observer_challenge_window_ms: 5_000,
        max_reassignment_depth: 0,
        max_checkpoint_staleness_ms: 120_000,
    };
    let validators = vec![
        header.producer_account_id,
        AccountId([51u8; 32]),
        AccountId([52u8; 32]),
        AccountId([53u8; 32]),
    ];
    let observer_assignments = derive_asymptote_observer_assignments(
        &witness_seed,
        &build_validator_sets(validators.clone()).current,
        header.producer_account_id,
        header.height,
        header.view,
        policy.observer_rounds,
        policy.observer_committee_size,
    )
    .unwrap();
    let observer_assignments_hash =
        canonical_asymptote_observer_assignments_hash(&observer_assignments).unwrap();

    let observer_log_keypair = Keypair::generate_ed25519();
    let mut observer_manifests = Vec::new();
    let mut observer_descriptors = vec![guardian_log_descriptor];
    let mut anchored_checkpoints = vec![header
        .guardian_certificate
        .as_ref()
        .unwrap()
        .log_checkpoint
        .as_ref()
        .unwrap()
        .clone()];
    let base_certificate = header.guardian_certificate.as_ref().unwrap().clone();
    let selected_accounts = observer_assignments
        .iter()
        .map(|assignment| assignment.observer_account_id)
        .collect::<std::collections::HashSet<_>>();
    let mut selected_manifests = HashMap::new();
    for account in validators
        .iter()
        .copied()
        .filter(|account| *account != header.producer_account_id)
    {
        let member_keys = vec![
            BlsKeyPair::generate().unwrap(),
            BlsKeyPair::generate().unwrap(),
            BlsKeyPair::generate().unwrap(),
        ];
        let log_id = format!("observer-canonical-{}", hex::encode(account.as_ref()));
        let observer_manifest =
            build_observer_manifest(account, manifest.epoch, [81u8; 32], &log_id, &member_keys);
        if selected_accounts.contains(&account) {
            selected_manifests.insert(account, (observer_manifest.clone(), member_keys));
        }
        observer_manifests.push(observer_manifest);
    }

    let mut observer_transcripts = Vec::new();
    for assignment in observer_assignments {
        let (observer_manifest, member_keys) = selected_manifests
            .remove(&assignment.observer_account_id)
            .unwrap();
        let provisional = AsymptoteObserverCertificate {
            assignment: assignment.clone(),
            verdict: AsymptoteObserverVerdict::Ok,
            veto_kind: None,
            evidence_hash: [0u8; 32],
            guardian_certificate: GuardianQuorumCertificate::default(),
        };
        let statement = engine
            .asymptote_observer_statement(&header, &base_certificate, &provisional)
            .unwrap();
        let decision = GuardianDecision {
            domain: GuardianDecisionDomain::AsymptoteObserve as u8,
            subject: assignment.observer_account_id.0.to_vec(),
            payload_hash: ioi_crypto::algorithms::hash::sha256(
                &codec::to_bytes_canonical(&statement).unwrap(),
            )
            .unwrap(),
            counter: u64::from(assignment.round) + 1,
            trace_hash: [assignment.round as u8 + 11; 32],
            measurement_root: observer_manifest.measurement_profile_root,
            policy_hash: observer_manifest.policy_hash,
        };
        let mut observer_guardian_certificate = sign_decision_with_members(
            &observer_manifest,
            &decision,
            decision.counter,
            decision.trace_hash,
            &[
                (0, member_keys[0].private_key()),
                (1, member_keys[1].private_key()),
            ],
        )
        .unwrap();
        let checkpoint_entry =
            codec::to_bytes_canonical(&(decision.clone(), observer_guardian_certificate.clone()))
                .unwrap();
        observer_guardian_certificate.log_checkpoint = Some(build_signed_checkpoint(
            &observer_manifest.transparency_log_id,
            &observer_log_keypair,
            &[checkpoint_entry],
            0,
            u64::from(assignment.round) + 50,
        ));
        anchored_checkpoints.push(
            observer_guardian_certificate
                .log_checkpoint
                .as_ref()
                .unwrap()
                .clone(),
        );
        observer_descriptors.push(build_log_descriptor(
            &observer_manifest.transparency_log_id,
            &observer_log_keypair,
        ));
        observer_transcripts.push(AsymptoteObserverTranscript {
            statement,
            guardian_certificate: observer_guardian_certificate,
        });
    }

    let observer_challenges = Vec::<AsymptoteObserverChallenge>::new();
    let transcripts_root =
        canonical_asymptote_observer_transcripts_hash(&observer_transcripts).unwrap();
    let challenges_root =
        canonical_asymptote_observer_challenges_hash(&observer_challenges).unwrap();
    let transcript_commitment = AsymptoteObserverTranscriptCommitment {
        epoch: manifest.epoch,
        height: header.height,
        view: header.view,
        assignments_hash: observer_assignments_hash,
        transcripts_root,
        transcript_count: observer_transcripts.len() as u16,
    };
    let challenge_commitment = AsymptoteObserverChallengeCommitment {
        epoch: manifest.epoch,
        height: header.height,
        view: header.view,
        challenges_root,
        challenge_count: 0,
    };
    let canonical_close = AsymptoteObserverCanonicalClose {
        epoch: manifest.epoch,
        height: header.height,
        view: header.view,
        assignments_hash: observer_assignments_hash,
        transcripts_root,
        challenges_root,
        transcript_count: observer_transcripts.len() as u16,
        challenge_count: 0,
        challenge_cutoff_timestamp_ms: 25_000,
    };

    header.sealed_finality_proof = Some(SealedFinalityProof {
        epoch: manifest.epoch,
        finality_tier: FinalityTier::SealedFinal,
        collapse_state: CollapseState::SealedFinal,
        guardian_manifest_hash: base_certificate.manifest_hash,
        guardian_decision_hash: base_certificate.decision_hash,
        guardian_counter: base_certificate.counter,
        guardian_trace_hash: base_certificate.trace_hash,
        guardian_measurement_root: base_certificate.measurement_root,
        policy_hash: manifest.policy_hash,
        witness_certificates: Vec::new(),
        observer_certificates: Vec::new(),
        observer_close_certificate: None,
        observer_transcripts: observer_transcripts.clone(),
        observer_challenges: observer_challenges.clone(),
        observer_transcript_commitment: Some(transcript_commitment.clone()),
        observer_challenge_commitment: Some(challenge_commitment.clone()),
        observer_canonical_close: Some(canonical_close.clone()),
        observer_canonical_abort: None,
        veto_proofs: Vec::new(),
        divergence_signals: Vec::new(),
        proof_signature: SignatureProof::default(),
    });
    sign_test_sealed_finality_proof(
        header.sealed_finality_proof.as_mut().unwrap(),
        &guardian_log_keypair,
    );

    let mut parent_view = build_parent_view_with_asymptote_observers(
        &manifest,
        &observer_descriptors,
        policy,
        witness_seed,
        &anchored_checkpoints,
        validators,
        &observer_manifests,
    );
    parent_view.state.insert(
        guardian_registry_observer_transcript_commitment_key(
            manifest.epoch,
            header.height,
            header.view,
        ),
        codec::to_bytes_canonical(&transcript_commitment).unwrap(),
    );
    parent_view.state.insert(
        guardian_registry_observer_challenge_commitment_key(
            manifest.epoch,
            header.height,
            header.view,
        ),
        codec::to_bytes_canonical(&challenge_commitment).unwrap(),
    );
    parent_view.state.insert(
        guardian_registry_observer_canonical_close_key(manifest.epoch, header.height, header.view),
        codec::to_bytes_canonical(&canonical_close).unwrap(),
    );

    engine
        .verify_guardianized_certificate(&header, &preimage, &parent_view)
        .await
        .unwrap();
}

#[tokio::test]
async fn asymptote_accepts_canonical_observer_sealed_finality_proof_without_registry_copies() {
    let mut fixture = build_canonical_observer_fixture();
    let base_certificate = fixture
        .header
        .guardian_certificate
        .as_ref()
        .unwrap()
        .clone();
    let observer_assignments_hash =
        canonical_asymptote_observer_assignments_hash(&fixture.observer_assignments).unwrap();
    let observer_challenges = Vec::<AsymptoteObserverChallenge>::new();
    let transcripts_root =
        canonical_asymptote_observer_transcripts_hash(&fixture.observer_transcripts).unwrap();
    let challenges_root =
        canonical_asymptote_observer_challenges_hash(&observer_challenges).unwrap();
    let transcript_commitment = AsymptoteObserverTranscriptCommitment {
        epoch: fixture.manifest.epoch,
        height: fixture.header.height,
        view: fixture.header.view,
        assignments_hash: observer_assignments_hash,
        transcripts_root,
        transcript_count: fixture.observer_transcripts.len() as u16,
    };
    let challenge_commitment = AsymptoteObserverChallengeCommitment {
        epoch: fixture.manifest.epoch,
        height: fixture.header.height,
        view: fixture.header.view,
        challenges_root,
        challenge_count: 0,
    };
    let canonical_close = AsymptoteObserverCanonicalClose {
        epoch: fixture.manifest.epoch,
        height: fixture.header.height,
        view: fixture.header.view,
        assignments_hash: observer_assignments_hash,
        transcripts_root,
        challenges_root,
        transcript_count: fixture.observer_transcripts.len() as u16,
        challenge_count: 0,
        challenge_cutoff_timestamp_ms: 30_000,
    };

    fixture.header.sealed_finality_proof = Some(SealedFinalityProof {
        epoch: fixture.manifest.epoch,
        finality_tier: FinalityTier::SealedFinal,
        collapse_state: CollapseState::SealedFinal,
        guardian_manifest_hash: base_certificate.manifest_hash,
        guardian_decision_hash: base_certificate.decision_hash,
        guardian_counter: base_certificate.counter,
        guardian_trace_hash: base_certificate.trace_hash,
        guardian_measurement_root: base_certificate.measurement_root,
        policy_hash: fixture.manifest.policy_hash,
        witness_certificates: Vec::new(),
        observer_certificates: Vec::new(),
        observer_close_certificate: None,
        observer_transcripts: fixture.observer_transcripts.clone(),
        observer_challenges: observer_challenges.clone(),
        observer_transcript_commitment: Some(transcript_commitment),
        observer_challenge_commitment: Some(challenge_commitment),
        observer_canonical_close: Some(canonical_close),
        observer_canonical_abort: None,
        veto_proofs: Vec::new(),
        divergence_signals: Vec::new(),
        proof_signature: SignatureProof::default(),
    });
    sign_test_sealed_finality_proof(
        fixture.header.sealed_finality_proof.as_mut().unwrap(),
        &fixture.guardian_log_keypair,
    );

    let parent_view = canonical_observer_parent_view(&fixture);
    fixture
        .engine
        .verify_guardianized_certificate(&fixture.header, &fixture.preimage, &parent_view)
        .await
        .unwrap();
}

#[tokio::test]
async fn asymptote_rejects_canonical_observer_sealed_finality_proof_with_mismatched_registry_copy()
{
    let mut fixture = build_canonical_observer_fixture();
    let base_certificate = fixture
        .header
        .guardian_certificate
        .as_ref()
        .unwrap()
        .clone();
    let observer_assignments_hash =
        canonical_asymptote_observer_assignments_hash(&fixture.observer_assignments).unwrap();
    let observer_challenges = Vec::<AsymptoteObserverChallenge>::new();
    let transcripts_root =
        canonical_asymptote_observer_transcripts_hash(&fixture.observer_transcripts).unwrap();
    let challenges_root =
        canonical_asymptote_observer_challenges_hash(&observer_challenges).unwrap();
    let transcript_commitment = AsymptoteObserverTranscriptCommitment {
        epoch: fixture.manifest.epoch,
        height: fixture.header.height,
        view: fixture.header.view,
        assignments_hash: observer_assignments_hash,
        transcripts_root,
        transcript_count: fixture.observer_transcripts.len() as u16,
    };
    let challenge_commitment = AsymptoteObserverChallengeCommitment {
        epoch: fixture.manifest.epoch,
        height: fixture.header.height,
        view: fixture.header.view,
        challenges_root,
        challenge_count: 0,
    };
    let canonical_close = AsymptoteObserverCanonicalClose {
        epoch: fixture.manifest.epoch,
        height: fixture.header.height,
        view: fixture.header.view,
        assignments_hash: observer_assignments_hash,
        transcripts_root,
        challenges_root,
        transcript_count: fixture.observer_transcripts.len() as u16,
        challenge_count: 0,
        challenge_cutoff_timestamp_ms: 31_000,
    };

    fixture.header.sealed_finality_proof = Some(SealedFinalityProof {
        epoch: fixture.manifest.epoch,
        finality_tier: FinalityTier::SealedFinal,
        collapse_state: CollapseState::SealedFinal,
        guardian_manifest_hash: base_certificate.manifest_hash,
        guardian_decision_hash: base_certificate.decision_hash,
        guardian_counter: base_certificate.counter,
        guardian_trace_hash: base_certificate.trace_hash,
        guardian_measurement_root: base_certificate.measurement_root,
        policy_hash: fixture.manifest.policy_hash,
        witness_certificates: Vec::new(),
        observer_certificates: Vec::new(),
        observer_close_certificate: None,
        observer_transcripts: fixture.observer_transcripts.clone(),
        observer_challenges: observer_challenges.clone(),
        observer_transcript_commitment: Some(transcript_commitment.clone()),
        observer_challenge_commitment: Some(challenge_commitment),
        observer_canonical_close: Some(canonical_close),
        observer_canonical_abort: None,
        veto_proofs: Vec::new(),
        divergence_signals: Vec::new(),
        proof_signature: SignatureProof::default(),
    });
    sign_test_sealed_finality_proof(
        fixture.header.sealed_finality_proof.as_mut().unwrap(),
        &fixture.guardian_log_keypair,
    );

    let mut parent_view = canonical_observer_parent_view(&fixture);
    let mut mismatched_transcript_commitment = transcript_commitment;
    mismatched_transcript_commitment.transcripts_root = [0xabu8; 32];
    parent_view.state.insert(
        guardian_registry_observer_transcript_commitment_key(
            fixture.manifest.epoch,
            fixture.header.height,
            fixture.header.view,
        ),
        codec::to_bytes_canonical(&mismatched_transcript_commitment).unwrap(),
    );

    let err = fixture
        .engine
        .verify_guardianized_certificate(&fixture.header, &fixture.preimage, &parent_view)
        .await
        .unwrap_err();
    assert!(err
        .to_string()
        .contains("observer transcript commitment does not match the on-chain registry copy"));
}

#[tokio::test]
async fn asymptote_accepts_canonical_observer_abort_proof() {
    let mut fixture = build_canonical_observer_fixture();
    let base_certificate = fixture
        .header
        .guardian_certificate
        .as_ref()
        .unwrap()
        .clone();
    let observer_assignments_hash =
        canonical_asymptote_observer_assignments_hash(&fixture.observer_assignments).unwrap();
    let challenged_assignment = fixture.observer_assignments[0].clone();
    let observer_transcripts = fixture
        .observer_transcripts
        .iter()
        .filter(|transcript| transcript.statement.assignment != challenged_assignment)
        .cloned()
        .collect::<Vec<_>>();
    let mut challenge = AsymptoteObserverChallenge {
        challenge_id: [0u8; 32],
        epoch: fixture.manifest.epoch,
        height: fixture.header.height,
        view: fixture.header.view,
        kind: AsymptoteObserverChallengeKind::MissingTranscript,
        challenger_account_id: fixture.header.producer_account_id,
        assignment: Some(challenged_assignment),
        observation_request: None,
        transcript: None,
        canonical_close: None,
        evidence_hash: canonical_asymptote_observer_assignment_hash(
            &fixture.observer_assignments[0],
        )
        .unwrap(),
        details: "observer transcript was omitted from the canonical surface".into(),
    };
    finalize_observer_challenge_id(&mut challenge);
    let observer_challenges = vec![challenge.clone()];
    let transcripts_root =
        canonical_asymptote_observer_transcripts_hash(&observer_transcripts).unwrap();
    let challenges_root =
        canonical_asymptote_observer_challenges_hash(&observer_challenges).unwrap();
    let transcript_commitment = AsymptoteObserverTranscriptCommitment {
        epoch: fixture.manifest.epoch,
        height: fixture.header.height,
        view: fixture.header.view,
        assignments_hash: observer_assignments_hash,
        transcripts_root,
        transcript_count: observer_transcripts.len() as u16,
    };
    let challenge_commitment = AsymptoteObserverChallengeCommitment {
        epoch: fixture.manifest.epoch,
        height: fixture.header.height,
        view: fixture.header.view,
        challenges_root,
        challenge_count: observer_challenges.len() as u16,
    };
    let canonical_abort = AsymptoteObserverCanonicalAbort {
        epoch: fixture.manifest.epoch,
        height: fixture.header.height,
        view: fixture.header.view,
        assignments_hash: observer_assignments_hash,
        transcripts_root,
        challenges_root,
        transcript_count: observer_transcripts.len() as u16,
        challenge_count: observer_challenges.len() as u16,
        challenge_cutoff_timestamp_ms: 32_000,
    };

    fixture.header.sealed_finality_proof = Some(SealedFinalityProof {
        epoch: fixture.manifest.epoch,
        finality_tier: FinalityTier::BaseFinal,
        collapse_state: CollapseState::Abort,
        guardian_manifest_hash: base_certificate.manifest_hash,
        guardian_decision_hash: base_certificate.decision_hash,
        guardian_counter: base_certificate.counter,
        guardian_trace_hash: base_certificate.trace_hash,
        guardian_measurement_root: base_certificate.measurement_root,
        policy_hash: fixture.manifest.policy_hash,
        witness_certificates: Vec::new(),
        observer_certificates: Vec::new(),
        observer_close_certificate: None,
        observer_transcripts: observer_transcripts.clone(),
        observer_challenges: observer_challenges.clone(),
        observer_transcript_commitment: Some(transcript_commitment.clone()),
        observer_challenge_commitment: Some(challenge_commitment.clone()),
        observer_canonical_close: None,
        observer_canonical_abort: Some(canonical_abort.clone()),
        veto_proofs: Vec::new(),
        divergence_signals: Vec::new(),
        proof_signature: SignatureProof::default(),
    });
    sign_test_sealed_finality_proof(
        fixture.header.sealed_finality_proof.as_mut().unwrap(),
        &fixture.guardian_log_keypair,
    );

    let mut parent_view = canonical_observer_parent_view(&fixture);
    parent_view.state.insert(
        guardian_registry_observer_transcript_commitment_key(
            fixture.manifest.epoch,
            fixture.header.height,
            fixture.header.view,
        ),
        codec::to_bytes_canonical(&transcript_commitment).unwrap(),
    );
    parent_view.state.insert(
        guardian_registry_observer_challenge_commitment_key(
            fixture.manifest.epoch,
            fixture.header.height,
            fixture.header.view,
        ),
        codec::to_bytes_canonical(&challenge_commitment).unwrap(),
    );
    parent_view.state.insert(
        guardian_registry_observer_canonical_abort_key(
            fixture.manifest.epoch,
            fixture.header.height,
            fixture.header.view,
        ),
        codec::to_bytes_canonical(&canonical_abort).unwrap(),
    );

    fixture
        .engine
        .verify_guardianized_certificate(&fixture.header, &fixture.preimage, &parent_view)
        .await
        .unwrap();
}

#[tokio::test]
async fn asymptote_accepts_invalid_canonical_close_challenge_abort_proof() {
    let mut fixture = build_canonical_observer_fixture();
    let base_certificate = fixture
        .header
        .guardian_certificate
        .as_ref()
        .unwrap()
        .clone();
    let observer_assignments_hash =
        canonical_asymptote_observer_assignments_hash(&fixture.observer_assignments).unwrap();
    let observer_transcripts = fixture.observer_transcripts.clone();
    let transcripts_root =
        canonical_asymptote_observer_transcripts_hash(&observer_transcripts).unwrap();
    let empty_challenges: Vec<AsymptoteObserverChallenge> = Vec::new();
    let empty_challenges_root =
        canonical_asymptote_observer_challenges_hash(&empty_challenges).unwrap();
    let mut invalid_close = AsymptoteObserverCanonicalClose {
        epoch: fixture.manifest.epoch,
        height: fixture.header.height,
        view: fixture.header.view,
        assignments_hash: observer_assignments_hash,
        transcripts_root,
        challenges_root: empty_challenges_root,
        transcript_count: observer_transcripts.len() as u16,
        challenge_count: 0,
        challenge_cutoff_timestamp_ms: 34_000,
    };
    invalid_close.transcripts_root[0] ^= 0xFF;
    let mut challenge = AsymptoteObserverChallenge {
        challenge_id: [0u8; 32],
        epoch: fixture.manifest.epoch,
        height: fixture.header.height,
        view: fixture.header.view,
        kind: AsymptoteObserverChallengeKind::InvalidCanonicalClose,
        challenger_account_id: fixture.header.producer_account_id,
        assignment: None,
        observation_request: None,
        transcript: None,
        canonical_close: Some(invalid_close.clone()),
        evidence_hash: canonical_asymptote_observer_canonical_close_hash(&invalid_close).unwrap(),
        details: "proof-carried canonical close does not match the transcript surface".into(),
    };
    finalize_observer_challenge_id(&mut challenge);
    let observer_challenges = vec![challenge];
    let challenges_root =
        canonical_asymptote_observer_challenges_hash(&observer_challenges).unwrap();
    let transcript_commitment = AsymptoteObserverTranscriptCommitment {
        epoch: fixture.manifest.epoch,
        height: fixture.header.height,
        view: fixture.header.view,
        assignments_hash: observer_assignments_hash,
        transcripts_root,
        transcript_count: observer_transcripts.len() as u16,
    };
    let challenge_commitment = AsymptoteObserverChallengeCommitment {
        epoch: fixture.manifest.epoch,
        height: fixture.header.height,
        view: fixture.header.view,
        challenges_root,
        challenge_count: observer_challenges.len() as u16,
    };
    let canonical_abort = AsymptoteObserverCanonicalAbort {
        epoch: fixture.manifest.epoch,
        height: fixture.header.height,
        view: fixture.header.view,
        assignments_hash: observer_assignments_hash,
        transcripts_root,
        challenges_root,
        transcript_count: observer_transcripts.len() as u16,
        challenge_count: observer_challenges.len() as u16,
        challenge_cutoff_timestamp_ms: 34_000,
    };

    fixture.header.sealed_finality_proof = Some(SealedFinalityProof {
        epoch: fixture.manifest.epoch,
        finality_tier: FinalityTier::BaseFinal,
        collapse_state: CollapseState::Abort,
        guardian_manifest_hash: base_certificate.manifest_hash,
        guardian_decision_hash: base_certificate.decision_hash,
        guardian_counter: base_certificate.counter,
        guardian_trace_hash: base_certificate.trace_hash,
        guardian_measurement_root: base_certificate.measurement_root,
        policy_hash: fixture.manifest.policy_hash,
        witness_certificates: Vec::new(),
        observer_certificates: Vec::new(),
        observer_close_certificate: None,
        observer_transcripts: observer_transcripts.clone(),
        observer_challenges: observer_challenges.clone(),
        observer_transcript_commitment: Some(transcript_commitment.clone()),
        observer_challenge_commitment: Some(challenge_commitment.clone()),
        observer_canonical_close: None,
        observer_canonical_abort: Some(canonical_abort.clone()),
        veto_proofs: Vec::new(),
        divergence_signals: Vec::new(),
        proof_signature: SignatureProof::default(),
    });
    sign_test_sealed_finality_proof(
        fixture.header.sealed_finality_proof.as_mut().unwrap(),
        &fixture.guardian_log_keypair,
    );

    let mut parent_view = canonical_observer_parent_view(&fixture);
    parent_view.state.insert(
        guardian_registry_observer_transcript_commitment_key(
            fixture.manifest.epoch,
            fixture.header.height,
            fixture.header.view,
        ),
        codec::to_bytes_canonical(&transcript_commitment).unwrap(),
    );
    parent_view.state.insert(
        guardian_registry_observer_challenge_commitment_key(
            fixture.manifest.epoch,
            fixture.header.height,
            fixture.header.view,
        ),
        codec::to_bytes_canonical(&challenge_commitment).unwrap(),
    );
    parent_view.state.insert(
        guardian_registry_observer_canonical_abort_key(
            fixture.manifest.epoch,
            fixture.header.height,
            fixture.header.view,
        ),
        codec::to_bytes_canonical(&canonical_abort).unwrap(),
    );

    fixture
        .engine
        .verify_guardianized_certificate(&fixture.header, &fixture.preimage, &parent_view)
        .await
        .unwrap();
}

#[tokio::test]
async fn asymptote_rejects_missing_transcript_challenge_with_wrong_assignment_hash() {
    let mut fixture = build_canonical_observer_fixture();
    let base_certificate = fixture
        .header
        .guardian_certificate
        .as_ref()
        .unwrap()
        .clone();
    let observer_assignments_hash =
        canonical_asymptote_observer_assignments_hash(&fixture.observer_assignments).unwrap();
    let challenged_assignment = fixture.observer_assignments[0].clone();
    let observer_transcripts = fixture
        .observer_transcripts
        .iter()
        .filter(|transcript| transcript.statement.assignment != challenged_assignment)
        .cloned()
        .collect::<Vec<_>>();
    let mut challenge = AsymptoteObserverChallenge {
        challenge_id: [0u8; 32],
        epoch: fixture.manifest.epoch,
        height: fixture.header.height,
        view: fixture.header.view,
        kind: AsymptoteObserverChallengeKind::MissingTranscript,
        challenger_account_id: fixture.header.producer_account_id,
        assignment: Some(challenged_assignment),
        observation_request: None,
        transcript: None,
        canonical_close: None,
        evidence_hash: [0xAAu8; 32],
        details: "observer transcript was omitted from the canonical surface".into(),
    };
    finalize_observer_challenge_id(&mut challenge);
    let observer_challenges = vec![challenge];
    let transcripts_root =
        canonical_asymptote_observer_transcripts_hash(&observer_transcripts).unwrap();
    let challenges_root =
        canonical_asymptote_observer_challenges_hash(&observer_challenges).unwrap();
    let transcript_commitment = AsymptoteObserverTranscriptCommitment {
        epoch: fixture.manifest.epoch,
        height: fixture.header.height,
        view: fixture.header.view,
        assignments_hash: observer_assignments_hash,
        transcripts_root,
        transcript_count: observer_transcripts.len() as u16,
    };
    let challenge_commitment = AsymptoteObserverChallengeCommitment {
        epoch: fixture.manifest.epoch,
        height: fixture.header.height,
        view: fixture.header.view,
        challenges_root,
        challenge_count: observer_challenges.len() as u16,
    };
    let canonical_abort = AsymptoteObserverCanonicalAbort {
        epoch: fixture.manifest.epoch,
        height: fixture.header.height,
        view: fixture.header.view,
        assignments_hash: observer_assignments_hash,
        transcripts_root,
        challenges_root,
        transcript_count: observer_transcripts.len() as u16,
        challenge_count: observer_challenges.len() as u16,
        challenge_cutoff_timestamp_ms: 35_000,
    };

    fixture.header.sealed_finality_proof = Some(SealedFinalityProof {
        epoch: fixture.manifest.epoch,
        finality_tier: FinalityTier::BaseFinal,
        collapse_state: CollapseState::Abort,
        guardian_manifest_hash: base_certificate.manifest_hash,
        guardian_decision_hash: base_certificate.decision_hash,
        guardian_counter: base_certificate.counter,
        guardian_trace_hash: base_certificate.trace_hash,
        guardian_measurement_root: base_certificate.measurement_root,
        policy_hash: fixture.manifest.policy_hash,
        witness_certificates: Vec::new(),
        observer_certificates: Vec::new(),
        observer_close_certificate: None,
        observer_transcripts: observer_transcripts.clone(),
        observer_challenges: observer_challenges.clone(),
        observer_transcript_commitment: Some(transcript_commitment),
        observer_challenge_commitment: Some(challenge_commitment),
        observer_canonical_close: None,
        observer_canonical_abort: Some(canonical_abort),
        veto_proofs: Vec::new(),
        divergence_signals: Vec::new(),
        proof_signature: SignatureProof::default(),
    });
    sign_test_sealed_finality_proof(
        fixture.header.sealed_finality_proof.as_mut().unwrap(),
        &fixture.guardian_log_keypair,
    );

    let parent_view = canonical_observer_parent_view(&fixture);
    let err = fixture
        .engine
        .verify_guardianized_certificate(&fixture.header, &fixture.preimage, &parent_view)
        .await
        .unwrap_err();
    assert!(err
        .to_string()
        .contains("missing-transcript challenge evidence hash does not match the assignment"));
}

#[tokio::test]
async fn asymptote_rejects_invalid_canonical_close_challenge_when_close_is_valid() {
    let mut fixture = build_canonical_observer_fixture();
    let base_certificate = fixture
        .header
        .guardian_certificate
        .as_ref()
        .unwrap()
        .clone();
    let observer_assignments_hash =
        canonical_asymptote_observer_assignments_hash(&fixture.observer_assignments).unwrap();
    let observer_transcripts = fixture.observer_transcripts.clone();
    let transcripts_root =
        canonical_asymptote_observer_transcripts_hash(&observer_transcripts).unwrap();
    let empty_challenges: Vec<AsymptoteObserverChallenge> = Vec::new();
    let empty_challenges_root =
        canonical_asymptote_observer_challenges_hash(&empty_challenges).unwrap();
    let valid_close = AsymptoteObserverCanonicalClose {
        epoch: fixture.manifest.epoch,
        height: fixture.header.height,
        view: fixture.header.view,
        assignments_hash: observer_assignments_hash,
        transcripts_root,
        challenges_root: empty_challenges_root,
        transcript_count: observer_transcripts.len() as u16,
        challenge_count: 0,
        challenge_cutoff_timestamp_ms: 35_000,
    };
    let mut challenge = AsymptoteObserverChallenge {
        challenge_id: [0u8; 32],
        epoch: fixture.manifest.epoch,
        height: fixture.header.height,
        view: fixture.header.view,
        kind: AsymptoteObserverChallengeKind::InvalidCanonicalClose,
        challenger_account_id: fixture.header.producer_account_id,
        assignment: None,
        observation_request: None,
        transcript: None,
        canonical_close: Some(valid_close.clone()),
        evidence_hash: canonical_asymptote_observer_canonical_close_hash(&valid_close).unwrap(),
        details: "claiming a valid close is invalid should fail".into(),
    };
    finalize_observer_challenge_id(&mut challenge);
    let observer_challenges = vec![challenge];
    let challenges_root =
        canonical_asymptote_observer_challenges_hash(&observer_challenges).unwrap();
    let transcript_commitment = AsymptoteObserverTranscriptCommitment {
        epoch: fixture.manifest.epoch,
        height: fixture.header.height,
        view: fixture.header.view,
        assignments_hash: observer_assignments_hash,
        transcripts_root,
        transcript_count: observer_transcripts.len() as u16,
    };
    let challenge_commitment = AsymptoteObserverChallengeCommitment {
        epoch: fixture.manifest.epoch,
        height: fixture.header.height,
        view: fixture.header.view,
        challenges_root,
        challenge_count: observer_challenges.len() as u16,
    };
    let canonical_abort = AsymptoteObserverCanonicalAbort {
        epoch: fixture.manifest.epoch,
        height: fixture.header.height,
        view: fixture.header.view,
        assignments_hash: observer_assignments_hash,
        transcripts_root,
        challenges_root,
        transcript_count: observer_transcripts.len() as u16,
        challenge_count: observer_challenges.len() as u16,
        challenge_cutoff_timestamp_ms: 35_000,
    };

    fixture.header.sealed_finality_proof = Some(SealedFinalityProof {
        epoch: fixture.manifest.epoch,
        finality_tier: FinalityTier::BaseFinal,
        collapse_state: CollapseState::Abort,
        guardian_manifest_hash: base_certificate.manifest_hash,
        guardian_decision_hash: base_certificate.decision_hash,
        guardian_counter: base_certificate.counter,
        guardian_trace_hash: base_certificate.trace_hash,
        guardian_measurement_root: base_certificate.measurement_root,
        policy_hash: fixture.manifest.policy_hash,
        witness_certificates: Vec::new(),
        observer_certificates: Vec::new(),
        observer_close_certificate: None,
        observer_transcripts: observer_transcripts.clone(),
        observer_challenges: observer_challenges.clone(),
        observer_transcript_commitment: Some(transcript_commitment),
        observer_challenge_commitment: Some(challenge_commitment),
        observer_canonical_close: None,
        observer_canonical_abort: Some(canonical_abort),
        veto_proofs: Vec::new(),
        divergence_signals: Vec::new(),
        proof_signature: SignatureProof::default(),
    });
    sign_test_sealed_finality_proof(
        fixture.header.sealed_finality_proof.as_mut().unwrap(),
        &fixture.guardian_log_keypair,
    );

    let parent_view = canonical_observer_parent_view(&fixture);
    let err = fixture
        .engine
        .verify_guardianized_certificate(&fixture.header, &fixture.preimage, &parent_view)
        .await
        .unwrap_err();
    assert!(err.to_string().contains(
        "invalid-canonical-close challenge does not contain an objectively invalid close"
    ));
}

#[tokio::test]
async fn asymptote_rejects_sealed_final_canonical_close_when_challenge_surface_is_non_empty() {
    let mut fixture = build_canonical_observer_fixture();
    let base_certificate = fixture
        .header
        .guardian_certificate
        .as_ref()
        .unwrap()
        .clone();
    let observer_assignments_hash =
        canonical_asymptote_observer_assignments_hash(&fixture.observer_assignments).unwrap();
    let challenged_assignment = fixture.observer_assignments[0].clone();
    let observer_transcripts = fixture
        .observer_transcripts
        .iter()
        .filter(|transcript| transcript.statement.assignment != challenged_assignment)
        .cloned()
        .collect::<Vec<_>>();
    let mut challenge = AsymptoteObserverChallenge {
        challenge_id: [0u8; 32],
        epoch: fixture.manifest.epoch,
        height: fixture.header.height,
        view: fixture.header.view,
        kind: AsymptoteObserverChallengeKind::MissingTranscript,
        challenger_account_id: fixture.header.producer_account_id,
        assignment: Some(challenged_assignment),
        observation_request: None,
        transcript: None,
        canonical_close: None,
        evidence_hash: canonical_asymptote_observer_assignment_hash(
            &fixture.observer_assignments[0],
        )
        .unwrap(),
        details: "observer transcript missing at close".into(),
    };
    finalize_observer_challenge_id(&mut challenge);
    let observer_challenges = vec![challenge];
    let transcripts_root =
        canonical_asymptote_observer_transcripts_hash(&observer_transcripts).unwrap();
    let challenges_root =
        canonical_asymptote_observer_challenges_hash(&observer_challenges).unwrap();
    let transcript_commitment = AsymptoteObserverTranscriptCommitment {
        epoch: fixture.manifest.epoch,
        height: fixture.header.height,
        view: fixture.header.view,
        assignments_hash: observer_assignments_hash,
        transcripts_root,
        transcript_count: observer_transcripts.len() as u16,
    };
    let challenge_commitment = AsymptoteObserverChallengeCommitment {
        epoch: fixture.manifest.epoch,
        height: fixture.header.height,
        view: fixture.header.view,
        challenges_root,
        challenge_count: observer_challenges.len() as u16,
    };
    let canonical_close = AsymptoteObserverCanonicalClose {
        epoch: fixture.manifest.epoch,
        height: fixture.header.height,
        view: fixture.header.view,
        assignments_hash: observer_assignments_hash,
        transcripts_root,
        challenges_root,
        transcript_count: observer_transcripts.len() as u16,
        challenge_count: observer_challenges.len() as u16,
        challenge_cutoff_timestamp_ms: 33_000,
    };

    fixture.header.sealed_finality_proof = Some(SealedFinalityProof {
        epoch: fixture.manifest.epoch,
        finality_tier: FinalityTier::SealedFinal,
        collapse_state: CollapseState::SealedFinal,
        guardian_manifest_hash: base_certificate.manifest_hash,
        guardian_decision_hash: base_certificate.decision_hash,
        guardian_counter: base_certificate.counter,
        guardian_trace_hash: base_certificate.trace_hash,
        guardian_measurement_root: base_certificate.measurement_root,
        policy_hash: fixture.manifest.policy_hash,
        witness_certificates: Vec::new(),
        observer_certificates: Vec::new(),
        observer_close_certificate: None,
        observer_transcripts: observer_transcripts.clone(),
        observer_challenges: observer_challenges.clone(),
        observer_transcript_commitment: Some(transcript_commitment),
        observer_challenge_commitment: Some(challenge_commitment),
        observer_canonical_close: Some(canonical_close),
        observer_canonical_abort: None,
        veto_proofs: Vec::new(),
        divergence_signals: Vec::new(),
        proof_signature: SignatureProof::default(),
    });
    sign_test_sealed_finality_proof(
        fixture.header.sealed_finality_proof.as_mut().unwrap(),
        &fixture.guardian_log_keypair,
    );

    let parent_view = canonical_observer_parent_view(&fixture);
    let err = fixture
        .engine
        .verify_guardianized_certificate(&fixture.header, &fixture.preimage, &parent_view)
        .await
        .unwrap_err();
    let err_text = err.to_string();
    assert!(
        err_text.contains(
            "observer challenge surface is non-empty; canonical close is challenge-dominated"
        ) || err_text.contains("canonical observer close may not carry dominant challenges")
            || err_text.contains(
                "observer transcript counts do not match the deterministic assignment surface"
            ),
        "unexpected canonical-close rejection: {err_text}"
    );
}

#[tokio::test]
async fn asymptote_accepts_valid_canonical_order_certificate() {
    let (mut engine, mut header, manifest, preimage, _, log_keypair) =
        build_case(&[(0, 0), (1, 1)]);
    engine.safety_mode = AftSafetyMode::Asymptote;

    let bulletin = BulletinCommitment {
        height: header.height,
        cutoff_timestamp_ms: 1_750_000_001,
        bulletin_root: [61u8; 32],
        entry_count: 3,
    };
    let randomness_beacon = derive_reference_ordering_randomness_beacon(&header).unwrap();
    let template_certificate = CanonicalOrderCertificate {
        height: header.height,
        bulletin_commitment: bulletin.clone(),
        bulletin_availability_certificate: BulletinAvailabilityCertificate::default(),
        randomness_beacon,
        ordered_transactions_root_hash: [0u8; 32],
        resulting_state_root_hash: [0u8; 32],
        proof: CanonicalOrderProof {
            proof_system: CanonicalOrderProofSystem::HashBindingV1,
            public_inputs_hash: [0u8; 32],
            proof_bytes: Vec::new(),
        },
        omission_proofs: Vec::new(),
    };
    let public_inputs = canonical_order_public_inputs(&header, &template_certificate).unwrap();
    let public_inputs_hash = canonical_order_public_inputs_hash(&public_inputs).unwrap();
    let bulletin_availability_certificate = build_bulletin_availability_certificate(
        &bulletin,
        &randomness_beacon,
        &public_inputs.ordered_transactions_root_hash,
        &public_inputs.resulting_state_root_hash,
    )
    .unwrap();
    header.canonical_order_certificate = Some(CanonicalOrderCertificate {
        bulletin_availability_certificate,
        ordered_transactions_root_hash: public_inputs.ordered_transactions_root_hash,
        resulting_state_root_hash: public_inputs.resulting_state_root_hash,
        proof: CanonicalOrderProof {
            proof_system: CanonicalOrderProofSystem::HashBindingV1,
            public_inputs_hash,
            proof_bytes: build_reference_canonical_order_proof_bytes(public_inputs_hash).unwrap(),
        },
        ..template_certificate
    });

    let policy = AsymptotePolicy {
        epoch: manifest.epoch,
        high_risk_effect_tier: FinalityTier::SealedFinal,
        required_witness_strata: vec!["stratum-a".into()],
        escalation_witness_strata: vec!["stratum-a".into()],
        observer_rounds: 0,
        observer_committee_size: 0,
        max_reassignment_depth: 0,
        max_checkpoint_staleness_ms: 120_000,
        observer_correlation_budget: AsymptoteObserverCorrelationBudget::default(),
        observer_sealing_mode: AsymptoteObserverSealingMode::SampledCloseV1,
        observer_challenge_window_ms: 0,
    };
    let parent_view = build_parent_view_with_bulletin_commitment(
        &manifest,
        &[build_log_descriptor(
            &manifest.transparency_log_id,
            &log_keypair,
        )],
        policy,
        GuardianWitnessEpochSeed {
            epoch: manifest.epoch,
            seed: [63u8; 32],
            checkpoint_interval_blocks: 4,
            max_reassignment_depth: 0,
        },
        &[header
            .guardian_certificate
            .as_ref()
            .unwrap()
            .log_checkpoint
            .clone()
            .unwrap()],
        bulletin,
    );
    let mut parent_view = parent_view;
    let bulletin_availability_certificate = header
        .canonical_order_certificate
        .as_ref()
        .unwrap()
        .bulletin_availability_certificate
        .clone();
    parent_view.state.insert(
        aft_bulletin_availability_certificate_key(header.height),
        codec::to_bytes_canonical(&bulletin_availability_certificate).unwrap(),
    );
    let bulletin_close = build_canonical_bulletin_close(
        &header
            .canonical_order_certificate
            .as_ref()
            .unwrap()
            .bulletin_commitment,
        &bulletin_availability_certificate,
    )
    .unwrap();
    parent_view.state.insert(
        aft_canonical_bulletin_close_key(header.height),
        codec::to_bytes_canonical(&bulletin_close).unwrap(),
    );

    engine
        .verify_guardianized_certificate(&header, &preimage, &parent_view)
        .await
        .unwrap();
}

#[tokio::test]
async fn asymptote_rejects_canonical_order_certificate_with_mismatched_published_availability() {
    let (mut engine, mut header, manifest, preimage, _, log_keypair) =
        build_case(&[(0, 0), (1, 1)]);
    engine.safety_mode = AftSafetyMode::Asymptote;

    let bulletin = BulletinCommitment {
        height: header.height,
        cutoff_timestamp_ms: 1_750_000_001,
        bulletin_root: [81u8; 32],
        entry_count: 3,
    };
    let randomness_beacon = derive_reference_ordering_randomness_beacon(&header).unwrap();
    let template_certificate = CanonicalOrderCertificate {
        height: header.height,
        bulletin_commitment: bulletin.clone(),
        bulletin_availability_certificate: BulletinAvailabilityCertificate::default(),
        randomness_beacon,
        ordered_transactions_root_hash: [0u8; 32],
        resulting_state_root_hash: [0u8; 32],
        proof: CanonicalOrderProof {
            proof_system: CanonicalOrderProofSystem::HashBindingV1,
            public_inputs_hash: [0u8; 32],
            proof_bytes: Vec::new(),
        },
        omission_proofs: Vec::new(),
    };
    let public_inputs = canonical_order_public_inputs(&header, &template_certificate).unwrap();
    let public_inputs_hash = canonical_order_public_inputs_hash(&public_inputs).unwrap();
    let bulletin_availability_certificate = build_bulletin_availability_certificate(
        &bulletin,
        &randomness_beacon,
        &public_inputs.ordered_transactions_root_hash,
        &public_inputs.resulting_state_root_hash,
    )
    .unwrap();
    header.canonical_order_certificate = Some(CanonicalOrderCertificate {
        bulletin_availability_certificate,
        ordered_transactions_root_hash: public_inputs.ordered_transactions_root_hash,
        resulting_state_root_hash: public_inputs.resulting_state_root_hash,
        proof: CanonicalOrderProof {
            proof_system: CanonicalOrderProofSystem::HashBindingV1,
            public_inputs_hash,
            proof_bytes: build_reference_canonical_order_proof_bytes(public_inputs_hash).unwrap(),
        },
        ..template_certificate
    });

    let policy = AsymptotePolicy {
        epoch: manifest.epoch,
        high_risk_effect_tier: FinalityTier::SealedFinal,
        required_witness_strata: vec!["stratum-a".into()],
        escalation_witness_strata: vec!["stratum-a".into()],
        observer_rounds: 0,
        observer_committee_size: 0,
        max_reassignment_depth: 0,
        max_checkpoint_staleness_ms: 120_000,
        observer_correlation_budget: AsymptoteObserverCorrelationBudget::default(),
        observer_sealing_mode: AsymptoteObserverSealingMode::SampledCloseV1,
        observer_challenge_window_ms: 0,
    };
    let mut parent_view = build_parent_view_with_bulletin_commitment(
        &manifest,
        &[build_log_descriptor(
            &manifest.transparency_log_id,
            &log_keypair,
        )],
        policy,
        GuardianWitnessEpochSeed {
            epoch: manifest.epoch,
            seed: [82u8; 32],
            checkpoint_interval_blocks: 4,
            max_reassignment_depth: 0,
        },
        &[header
            .guardian_certificate
            .as_ref()
            .unwrap()
            .log_checkpoint
            .clone()
            .unwrap()],
        bulletin,
    );
    let mut mismatched_availability = header
        .canonical_order_certificate
        .as_ref()
        .unwrap()
        .bulletin_availability_certificate
        .clone();
    mismatched_availability.recoverability_root = [83u8; 32];
    parent_view.state.insert(
        aft_bulletin_availability_certificate_key(header.height),
        codec::to_bytes_canonical(&mismatched_availability).unwrap(),
    );

    let err = engine
        .verify_guardianized_certificate(&header, &preimage, &parent_view)
        .await
        .unwrap_err();
    assert!(err.to_string().contains(
            "canonical order certificate bulletin availability certificate does not match published bulletin availability"
        ));
}

#[tokio::test]
async fn asymptote_rejects_canonical_order_certificate_with_mismatched_published_bulletin_close() {
    let (mut engine, mut header, manifest, preimage, _, log_keypair) =
        build_case(&[(0, 0), (1, 1)]);
    engine.safety_mode = AftSafetyMode::Asymptote;

    let bulletin = BulletinCommitment {
        height: header.height,
        cutoff_timestamp_ms: 1_750_000_011,
        bulletin_root: [91u8; 32],
        entry_count: 3,
    };
    let randomness_beacon = derive_reference_ordering_randomness_beacon(&header).unwrap();
    let template_certificate = CanonicalOrderCertificate {
        height: header.height,
        bulletin_commitment: bulletin.clone(),
        bulletin_availability_certificate: BulletinAvailabilityCertificate::default(),
        randomness_beacon,
        ordered_transactions_root_hash: [0u8; 32],
        resulting_state_root_hash: [0u8; 32],
        proof: CanonicalOrderProof {
            proof_system: CanonicalOrderProofSystem::HashBindingV1,
            public_inputs_hash: [0u8; 32],
            proof_bytes: Vec::new(),
        },
        omission_proofs: Vec::new(),
    };
    let public_inputs = canonical_order_public_inputs(&header, &template_certificate).unwrap();
    let public_inputs_hash = canonical_order_public_inputs_hash(&public_inputs).unwrap();
    let bulletin_availability_certificate = build_bulletin_availability_certificate(
        &bulletin,
        &randomness_beacon,
        &public_inputs.ordered_transactions_root_hash,
        &public_inputs.resulting_state_root_hash,
    )
    .unwrap();
    header.canonical_order_certificate = Some(CanonicalOrderCertificate {
        bulletin_availability_certificate: bulletin_availability_certificate.clone(),
        ordered_transactions_root_hash: public_inputs.ordered_transactions_root_hash,
        resulting_state_root_hash: public_inputs.resulting_state_root_hash,
        proof: CanonicalOrderProof {
            proof_system: CanonicalOrderProofSystem::HashBindingV1,
            public_inputs_hash,
            proof_bytes: build_reference_canonical_order_proof_bytes(public_inputs_hash).unwrap(),
        },
        ..template_certificate
    });

    let policy = AsymptotePolicy {
        epoch: manifest.epoch,
        high_risk_effect_tier: FinalityTier::SealedFinal,
        required_witness_strata: vec!["stratum-a".into()],
        escalation_witness_strata: vec!["stratum-a".into()],
        observer_rounds: 0,
        observer_committee_size: 0,
        max_reassignment_depth: 0,
        max_checkpoint_staleness_ms: 120_000,
        observer_correlation_budget: AsymptoteObserverCorrelationBudget::default(),
        observer_sealing_mode: AsymptoteObserverSealingMode::SampledCloseV1,
        observer_challenge_window_ms: 0,
    };
    let mut parent_view = build_parent_view_with_bulletin_commitment(
        &manifest,
        &[build_log_descriptor(
            &manifest.transparency_log_id,
            &log_keypair,
        )],
        policy,
        GuardianWitnessEpochSeed {
            epoch: manifest.epoch,
            seed: [92u8; 32],
            checkpoint_interval_blocks: 4,
            max_reassignment_depth: 0,
        },
        &[header
            .guardian_certificate
            .as_ref()
            .unwrap()
            .log_checkpoint
            .clone()
            .unwrap()],
        bulletin,
    );
    parent_view.state.insert(
        aft_bulletin_availability_certificate_key(header.height),
        codec::to_bytes_canonical(&bulletin_availability_certificate).unwrap(),
    );
    let mut mismatched_bulletin_close = build_canonical_bulletin_close(
        &header
            .canonical_order_certificate
            .as_ref()
            .unwrap()
            .bulletin_commitment,
        &bulletin_availability_certificate,
    )
    .unwrap();
    mismatched_bulletin_close.entry_count = mismatched_bulletin_close.entry_count.saturating_add(1);
    parent_view.state.insert(
        aft_canonical_bulletin_close_key(header.height),
        codec::to_bytes_canonical(&mismatched_bulletin_close).unwrap(),
    );

    let err = engine
        .verify_guardianized_certificate(&header, &preimage, &parent_view)
        .await
        .unwrap_err();
    assert!(err
        .to_string()
        .contains("canonical bulletin close entry count does not match the bulletin commitment"));
}

#[tokio::test]
async fn asymptote_rejects_canonical_order_certificate_with_omission_proof() {
    let (mut engine, mut header, manifest, preimage, _, log_keypair) =
        build_case(&[(0, 0), (1, 1)]);
    engine.safety_mode = AftSafetyMode::Asymptote;

    let bulletin = BulletinCommitment {
        height: header.height,
        cutoff_timestamp_ms: 1_750_000_002,
        bulletin_root: [71u8; 32],
        entry_count: 2,
    };
    let randomness_beacon = derive_reference_ordering_randomness_beacon(&header).unwrap();
    let template_certificate = CanonicalOrderCertificate {
        height: header.height,
        bulletin_commitment: bulletin.clone(),
        bulletin_availability_certificate: BulletinAvailabilityCertificate::default(),
        randomness_beacon,
        ordered_transactions_root_hash: [0u8; 32],
        resulting_state_root_hash: [0u8; 32],
        proof: CanonicalOrderProof {
            proof_system: CanonicalOrderProofSystem::HashBindingV1,
            public_inputs_hash: [0u8; 32],
            proof_bytes: Vec::new(),
        },
        omission_proofs: vec![OmissionProof {
            height: header.height,
            offender_account_id: manifest.validator_account_id,
            tx_hash: [73u8; 32],
            bulletin_root: bulletin.bulletin_root,
            details: "omitted from canonical order".into(),
        }],
    };
    let public_inputs = canonical_order_public_inputs(&header, &template_certificate).unwrap();
    let public_inputs_hash = canonical_order_public_inputs_hash(&public_inputs).unwrap();
    let bulletin_availability_certificate = build_bulletin_availability_certificate(
        &bulletin,
        &randomness_beacon,
        &public_inputs.ordered_transactions_root_hash,
        &public_inputs.resulting_state_root_hash,
    )
    .unwrap();
    header.canonical_order_certificate = Some(CanonicalOrderCertificate {
        bulletin_availability_certificate,
        ordered_transactions_root_hash: public_inputs.ordered_transactions_root_hash,
        resulting_state_root_hash: public_inputs.resulting_state_root_hash,
        proof: CanonicalOrderProof {
            proof_system: CanonicalOrderProofSystem::HashBindingV1,
            public_inputs_hash,
            proof_bytes: build_reference_canonical_order_proof_bytes(public_inputs_hash).unwrap(),
        },
        ..template_certificate
    });

    let policy = AsymptotePolicy {
        epoch: manifest.epoch,
        high_risk_effect_tier: FinalityTier::SealedFinal,
        required_witness_strata: vec!["stratum-a".into()],
        escalation_witness_strata: vec!["stratum-a".into()],
        observer_rounds: 0,
        observer_committee_size: 0,
        max_reassignment_depth: 0,
        max_checkpoint_staleness_ms: 120_000,
        observer_correlation_budget: AsymptoteObserverCorrelationBudget::default(),
        observer_sealing_mode: AsymptoteObserverSealingMode::SampledCloseV1,
        observer_challenge_window_ms: 0,
    };
    let parent_view = build_parent_view_with_bulletin_commitment(
        &manifest,
        &[build_log_descriptor(
            &manifest.transparency_log_id,
            &log_keypair,
        )],
        policy,
        GuardianWitnessEpochSeed {
            epoch: manifest.epoch,
            seed: [74u8; 32],
            checkpoint_interval_blocks: 4,
            max_reassignment_depth: 0,
        },
        &[header
            .guardian_certificate
            .as_ref()
            .unwrap()
            .log_checkpoint
            .clone()
            .unwrap()],
        bulletin,
    );

    let err = engine
        .verify_guardianized_certificate(&header, &preimage, &parent_view)
        .await
        .unwrap_err();
    assert!(err
        .to_string()
        .contains("canonical order certificate is dominated by objective omission proofs"));
}

#[tokio::test]
async fn asymptote_rejects_canonical_order_certificate_when_published_abort_exists() {
    let (mut engine, mut header, manifest, preimage, _, log_keypair) =
        build_case(&[(0, 0), (1, 1)]);
    engine.safety_mode = AftSafetyMode::Asymptote;

    let bulletin = BulletinCommitment {
        height: header.height,
        cutoff_timestamp_ms: 1_750_000_021,
        bulletin_root: [101u8; 32],
        entry_count: 3,
    };
    let randomness_beacon = derive_reference_ordering_randomness_beacon(&header).unwrap();
    let template_certificate = CanonicalOrderCertificate {
        height: header.height,
        bulletin_commitment: bulletin.clone(),
        bulletin_availability_certificate: BulletinAvailabilityCertificate::default(),
        randomness_beacon,
        ordered_transactions_root_hash: [0u8; 32],
        resulting_state_root_hash: [0u8; 32],
        proof: CanonicalOrderProof {
            proof_system: CanonicalOrderProofSystem::HashBindingV1,
            public_inputs_hash: [0u8; 32],
            proof_bytes: Vec::new(),
        },
        omission_proofs: Vec::new(),
    };
    let public_inputs = canonical_order_public_inputs(&header, &template_certificate).unwrap();
    let public_inputs_hash = canonical_order_public_inputs_hash(&public_inputs).unwrap();
    let bulletin_availability_certificate = build_bulletin_availability_certificate(
        &bulletin,
        &randomness_beacon,
        &public_inputs.ordered_transactions_root_hash,
        &public_inputs.resulting_state_root_hash,
    )
    .unwrap();
    header.canonical_order_certificate = Some(CanonicalOrderCertificate {
        bulletin_availability_certificate,
        ordered_transactions_root_hash: public_inputs.ordered_transactions_root_hash,
        resulting_state_root_hash: public_inputs.resulting_state_root_hash,
        proof: CanonicalOrderProof {
            proof_system: CanonicalOrderProofSystem::HashBindingV1,
            public_inputs_hash,
            proof_bytes: build_reference_canonical_order_proof_bytes(public_inputs_hash).unwrap(),
        },
        ..template_certificate
    });

    let policy = AsymptotePolicy {
        epoch: manifest.epoch,
        high_risk_effect_tier: FinalityTier::SealedFinal,
        required_witness_strata: vec!["stratum-a".into()],
        escalation_witness_strata: vec!["stratum-a".into()],
        observer_rounds: 0,
        observer_committee_size: 0,
        max_reassignment_depth: 0,
        max_checkpoint_staleness_ms: 120_000,
        observer_correlation_budget: AsymptoteObserverCorrelationBudget::default(),
        observer_sealing_mode: AsymptoteObserverSealingMode::SampledCloseV1,
        observer_challenge_window_ms: 0,
    };
    let mut parent_view = build_parent_view_with_bulletin_commitment(
        &manifest,
        &[build_log_descriptor(
            &manifest.transparency_log_id,
            &log_keypair,
        )],
        policy,
        GuardianWitnessEpochSeed {
            epoch: manifest.epoch,
            seed: [102u8; 32],
            checkpoint_interval_blocks: 4,
            max_reassignment_depth: 0,
        },
        &[header
            .guardian_certificate
            .as_ref()
            .unwrap()
            .log_checkpoint
            .clone()
            .unwrap()],
        bulletin,
    );
    parent_view.state.insert(
        aft_canonical_order_abort_key(header.height),
        codec::to_bytes_canonical(&CanonicalOrderAbort {
            height: header.height,
            reason: CanonicalOrderAbortReason::InvalidProofBinding,
            details: "published canonical abort dominates a proof-binding failure".into(),
            bulletin_commitment_hash: [103u8; 32],
            bulletin_availability_certificate_hash: [104u8; 32],
            bulletin_close_hash: [106u8; 32],
            canonical_order_certificate_hash: [105u8; 32],
        })
        .unwrap(),
    );

    let err = engine
        .verify_guardianized_certificate(&header, &preimage, &parent_view)
        .await
        .unwrap_err();
    assert!(err
        .to_string()
        .contains("canonical order abort already dominates slot"));
}

#[tokio::test]
async fn asymptote_rejects_canonical_order_certificate_without_publication_frontier() {
    let (mut engine, mut header, manifest, preimage, _, log_keypair) =
        build_case(&[(0, 0), (1, 1)]);
    engine.safety_mode = AftSafetyMode::Asymptote;

    let bulletin = BulletinCommitment {
        height: header.height,
        cutoff_timestamp_ms: 1_750_000_026,
        bulletin_root: [107u8; 32],
        entry_count: 3,
    };
    let randomness_beacon = derive_reference_ordering_randomness_beacon(&header).unwrap();
    let template_certificate = CanonicalOrderCertificate {
        height: header.height,
        bulletin_commitment: bulletin.clone(),
        bulletin_availability_certificate: BulletinAvailabilityCertificate::default(),
        randomness_beacon,
        ordered_transactions_root_hash: [0u8; 32],
        resulting_state_root_hash: [0u8; 32],
        proof: CanonicalOrderProof {
            proof_system: CanonicalOrderProofSystem::HashBindingV1,
            public_inputs_hash: [0u8; 32],
            proof_bytes: Vec::new(),
        },
        omission_proofs: Vec::new(),
    };
    let public_inputs = canonical_order_public_inputs(&header, &template_certificate).unwrap();
    let public_inputs_hash = canonical_order_public_inputs_hash(&public_inputs).unwrap();
    let bulletin_availability_certificate = build_bulletin_availability_certificate(
        &bulletin,
        &randomness_beacon,
        &public_inputs.ordered_transactions_root_hash,
        &public_inputs.resulting_state_root_hash,
    )
    .unwrap();
    header.canonical_order_certificate = Some(CanonicalOrderCertificate {
        bulletin_availability_certificate,
        ordered_transactions_root_hash: public_inputs.ordered_transactions_root_hash,
        resulting_state_root_hash: public_inputs.resulting_state_root_hash,
        proof: CanonicalOrderProof {
            proof_system: CanonicalOrderProofSystem::HashBindingV1,
            public_inputs_hash,
            proof_bytes: build_reference_canonical_order_proof_bytes(public_inputs_hash).unwrap(),
        },
        ..template_certificate
    });

    let policy = AsymptotePolicy {
        epoch: manifest.epoch,
        high_risk_effect_tier: FinalityTier::SealedFinal,
        required_witness_strata: vec!["stratum-a".into()],
        escalation_witness_strata: vec!["stratum-a".into()],
        observer_rounds: 0,
        observer_committee_size: 0,
        max_reassignment_depth: 0,
        max_checkpoint_staleness_ms: 120_000,
        observer_correlation_budget: AsymptoteObserverCorrelationBudget::default(),
        observer_sealing_mode: AsymptoteObserverSealingMode::SampledCloseV1,
        observer_challenge_window_ms: 0,
    };
    let parent_view = build_parent_view_with_bulletin_commitment(
        &manifest,
        &[build_log_descriptor(
            &manifest.transparency_log_id,
            &log_keypair,
        )],
        policy,
        GuardianWitnessEpochSeed {
            epoch: manifest.epoch,
            seed: [108u8; 32],
            checkpoint_interval_blocks: 4,
            max_reassignment_depth: 0,
        },
        &[header
            .guardian_certificate
            .as_ref()
            .unwrap()
            .log_checkpoint
            .clone()
            .unwrap()],
        bulletin,
    );

    let err = engine
        .verify_guardianized_certificate(&header, &preimage, &parent_view)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("requires a publication frontier"));
}

#[tokio::test]
async fn asymptote_rejects_conflicting_published_publication_frontier() {
    let (mut engine, mut header, manifest, preimage, _, log_keypair) =
        build_case(&[(0, 0), (1, 1)]);
    engine.safety_mode = AftSafetyMode::Asymptote;

    let bulletin = BulletinCommitment {
        height: header.height,
        cutoff_timestamp_ms: 1_750_000_027,
        bulletin_root: [109u8; 32],
        entry_count: 3,
    };
    let randomness_beacon = derive_reference_ordering_randomness_beacon(&header).unwrap();
    let template_certificate = CanonicalOrderCertificate {
        height: header.height,
        bulletin_commitment: bulletin.clone(),
        bulletin_availability_certificate: BulletinAvailabilityCertificate::default(),
        randomness_beacon,
        ordered_transactions_root_hash: [0u8; 32],
        resulting_state_root_hash: [0u8; 32],
        proof: CanonicalOrderProof {
            proof_system: CanonicalOrderProofSystem::HashBindingV1,
            public_inputs_hash: [0u8; 32],
            proof_bytes: Vec::new(),
        },
        omission_proofs: Vec::new(),
    };
    let public_inputs = canonical_order_public_inputs(&header, &template_certificate).unwrap();
    let public_inputs_hash = canonical_order_public_inputs_hash(&public_inputs).unwrap();
    let bulletin_availability_certificate = build_bulletin_availability_certificate(
        &bulletin,
        &randomness_beacon,
        &public_inputs.ordered_transactions_root_hash,
        &public_inputs.resulting_state_root_hash,
    )
    .unwrap();
    header.canonical_order_certificate = Some(CanonicalOrderCertificate {
        bulletin_availability_certificate,
        ordered_transactions_root_hash: public_inputs.ordered_transactions_root_hash,
        resulting_state_root_hash: public_inputs.resulting_state_root_hash,
        proof: CanonicalOrderProof {
            proof_system: CanonicalOrderProofSystem::HashBindingV1,
            public_inputs_hash,
            proof_bytes: build_reference_canonical_order_proof_bytes(public_inputs_hash).unwrap(),
        },
        ..template_certificate
    });
    let frontier = build_publication_frontier(&header, None).unwrap();
    header.publication_frontier = Some(frontier.clone());

    let policy = AsymptotePolicy {
        epoch: manifest.epoch,
        high_risk_effect_tier: FinalityTier::SealedFinal,
        required_witness_strata: vec!["stratum-a".into()],
        escalation_witness_strata: vec!["stratum-a".into()],
        observer_rounds: 0,
        observer_committee_size: 0,
        max_reassignment_depth: 0,
        max_checkpoint_staleness_ms: 120_000,
        observer_correlation_budget: AsymptoteObserverCorrelationBudget::default(),
        observer_sealing_mode: AsymptoteObserverSealingMode::SampledCloseV1,
        observer_challenge_window_ms: 0,
    };
    let mut parent_view = build_parent_view_with_bulletin_commitment(
        &manifest,
        &[build_log_descriptor(
            &manifest.transparency_log_id,
            &log_keypair,
        )],
        policy,
        GuardianWitnessEpochSeed {
            epoch: manifest.epoch,
            seed: [110u8; 32],
            checkpoint_interval_blocks: 4,
            max_reassignment_depth: 0,
        },
        &[header
            .guardian_certificate
            .as_ref()
            .unwrap()
            .log_checkpoint
            .clone()
            .unwrap()],
        bulletin,
    );
    let mut conflicting_frontier = frontier.clone();
    conflicting_frontier.view += 1;
    conflicting_frontier.bulletin_commitment_hash[0] ^= 0xFF;
    parent_view.state.insert(
        aft_publication_frontier_key(header.height),
        codec::to_bytes_canonical(&conflicting_frontier).unwrap(),
    );

    let err = engine
        .verify_guardianized_certificate(&header, &preimage, &parent_view)
        .await
        .unwrap_err();
    assert!(err
        .to_string()
        .contains("conflicts with the published same-slot frontier"));
}

#[tokio::test]
async fn asymptote_accepts_abort_only_ordering_outcome_when_abort_is_published() {
    let (mut engine, header, manifest, preimage, _, log_keypair) = build_case(&[(0, 0), (1, 1)]);
    engine.safety_mode = AftSafetyMode::Asymptote;

    let bulletin = BulletinCommitment {
        height: header.height,
        cutoff_timestamp_ms: 1_750_000_031,
        bulletin_root: [111u8; 32],
        entry_count: 0,
    };
    let policy = AsymptotePolicy {
        epoch: manifest.epoch,
        high_risk_effect_tier: FinalityTier::SealedFinal,
        required_witness_strata: vec!["stratum-a".into()],
        escalation_witness_strata: vec!["stratum-a".into()],
        observer_rounds: 0,
        observer_committee_size: 0,
        max_reassignment_depth: 0,
        max_checkpoint_staleness_ms: 120_000,
        observer_correlation_budget: AsymptoteObserverCorrelationBudget::default(),
        observer_sealing_mode: AsymptoteObserverSealingMode::SampledCloseV1,
        observer_challenge_window_ms: 0,
    };
    let mut parent_view = build_parent_view_with_bulletin_commitment(
        &manifest,
        &[build_log_descriptor(
            &manifest.transparency_log_id,
            &log_keypair,
        )],
        policy,
        GuardianWitnessEpochSeed {
            epoch: manifest.epoch,
            seed: [112u8; 32],
            checkpoint_interval_blocks: 4,
            max_reassignment_depth: 0,
        },
        &[header
            .guardian_certificate
            .as_ref()
            .unwrap()
            .log_checkpoint
            .clone()
            .unwrap()],
        bulletin,
    );
    parent_view.state.insert(
        aft_canonical_order_abort_key(header.height),
        codec::to_bytes_canonical(&CanonicalOrderAbort {
            height: header.height,
            reason: CanonicalOrderAbortReason::BulletinSurfaceMismatch,
            details: "published canonical abort is the ordering outcome after a surface mismatch"
                .into(),
            bulletin_commitment_hash: [113u8; 32],
            bulletin_availability_certificate_hash: [114u8; 32],
            bulletin_close_hash: [115u8; 32],
            canonical_order_certificate_hash: [116u8; 32],
        })
        .unwrap(),
    );

    engine
        .verify_guardianized_certificate(&header, &preimage, &parent_view)
        .await
        .unwrap();
}

#[tokio::test]
async fn asymptote_rejects_abort_only_outcome_when_parent_state_coexists_with_positive_ordering_artifacts(
) {
    let (mut engine, header, manifest, preimage, _, log_keypair) = build_case(&[(0, 0), (1, 1)]);
    engine.safety_mode = AftSafetyMode::Asymptote;

    let bulletin = BulletinCommitment {
        height: header.height,
        cutoff_timestamp_ms: 1_750_000_041,
        bulletin_root: [121u8; 32],
        entry_count: 0,
    };
    let policy = AsymptotePolicy {
        epoch: manifest.epoch,
        high_risk_effect_tier: FinalityTier::SealedFinal,
        required_witness_strata: vec!["stratum-a".into()],
        escalation_witness_strata: vec!["stratum-a".into()],
        observer_rounds: 0,
        observer_committee_size: 0,
        max_reassignment_depth: 0,
        max_checkpoint_staleness_ms: 120_000,
        observer_correlation_budget: AsymptoteObserverCorrelationBudget::default(),
        observer_sealing_mode: AsymptoteObserverSealingMode::SampledCloseV1,
        observer_challenge_window_ms: 0,
    };
    let mut parent_view = build_parent_view_with_bulletin_commitment(
        &manifest,
        &[build_log_descriptor(
            &manifest.transparency_log_id,
            &log_keypair,
        )],
        policy,
        GuardianWitnessEpochSeed {
            epoch: manifest.epoch,
            seed: [122u8; 32],
            checkpoint_interval_blocks: 4,
            max_reassignment_depth: 0,
        },
        &[header
            .guardian_certificate
            .as_ref()
            .unwrap()
            .log_checkpoint
            .clone()
            .unwrap()],
        bulletin.clone(),
    );
    let bulletin_availability_certificate = BulletinAvailabilityCertificate {
        height: header.height,
        bulletin_commitment_hash: [123u8; 32],
        recoverability_root: [124u8; 32],
    };
    parent_view.state.insert(
        aft_bulletin_availability_certificate_key(header.height),
        codec::to_bytes_canonical(&bulletin_availability_certificate).unwrap(),
    );
    let bulletin_close =
        build_canonical_bulletin_close(&bulletin, &bulletin_availability_certificate).unwrap();
    parent_view.state.insert(
        aft_canonical_bulletin_close_key(header.height),
        codec::to_bytes_canonical(&bulletin_close).unwrap(),
    );
    parent_view.state.insert(
        aft_canonical_order_abort_key(header.height),
        codec::to_bytes_canonical(&CanonicalOrderAbort {
            height: header.height,
            reason: CanonicalOrderAbortReason::MissingOrderCertificate,
            details: "abort should not coexist with positive ordering artifacts".into(),
            bulletin_commitment_hash: [125u8; 32],
            bulletin_availability_certificate_hash: [126u8; 32],
            bulletin_close_hash: [127u8; 32],
            canonical_order_certificate_hash: [0u8; 32],
        })
        .unwrap(),
    );

    let err = engine
        .verify_guardianized_certificate(&header, &preimage, &parent_view)
        .await
        .unwrap_err();
    assert!(err
        .to_string()
        .contains("canonical order abort coexists with positive published ordering artifacts"));
}

#[tokio::test]
async fn asymptote_accepts_matching_published_canonical_collapse_object() {
    let (mut engine, header, manifest, _preimage, _, log_keypair) = build_case(&[(0, 0), (1, 1)]);
    engine.safety_mode = AftSafetyMode::Asymptote;

    let bulletin = BulletinCommitment {
        height: header.height,
        cutoff_timestamp_ms: 1_750_000_051,
        bulletin_root: [131u8; 32],
        entry_count: 0,
    };
    let policy = AsymptotePolicy {
        epoch: manifest.epoch,
        high_risk_effect_tier: FinalityTier::SealedFinal,
        required_witness_strata: vec!["stratum-a".into()],
        escalation_witness_strata: vec!["stratum-a".into()],
        observer_rounds: 0,
        observer_committee_size: 0,
        max_reassignment_depth: 0,
        max_checkpoint_staleness_ms: 120_000,
        observer_correlation_budget: AsymptoteObserverCorrelationBudget::default(),
        observer_sealing_mode: AsymptoteObserverSealingMode::SampledCloseV1,
        observer_challenge_window_ms: 0,
    };
    let mut parent_view = build_parent_view_with_bulletin_commitment(
        &manifest,
        &[build_log_descriptor(
            &manifest.transparency_log_id,
            &log_keypair,
        )],
        policy,
        GuardianWitnessEpochSeed {
            epoch: manifest.epoch,
            seed: [132u8; 32],
            checkpoint_interval_blocks: 4,
            max_reassignment_depth: 0,
        },
        &[header
            .guardian_certificate
            .as_ref()
            .unwrap()
            .log_checkpoint
            .clone()
            .unwrap()],
        bulletin,
    );
    let previous =
        test_canonical_collapse_object(header.height - 1, None, [210u8; 32], [211u8; 32]);
    parent_view.state.insert(
        aft_canonical_collapse_object_key(previous.height),
        codec::to_bytes_canonical(&previous).unwrap(),
    );
    let collapse =
        derive_canonical_collapse_object_with_previous(&header, &[], Some(&previous)).unwrap();
    parent_view.state.insert(
        aft_canonical_collapse_object_key(header.height),
        codec::to_bytes_canonical(&collapse).unwrap(),
    );

    engine
        .verify_published_canonical_collapse_object(&header, &parent_view)
        .await
        .unwrap();
}

#[tokio::test]
async fn asymptote_rejects_mismatched_published_canonical_collapse_object() {
    let (mut engine, header, manifest, _preimage, _, log_keypair) = build_case(&[(0, 0), (1, 1)]);
    engine.safety_mode = AftSafetyMode::Asymptote;

    let bulletin = BulletinCommitment {
        height: header.height,
        cutoff_timestamp_ms: 1_750_000_061,
        bulletin_root: [141u8; 32],
        entry_count: 0,
    };
    let policy = AsymptotePolicy {
        epoch: manifest.epoch,
        high_risk_effect_tier: FinalityTier::SealedFinal,
        required_witness_strata: vec!["stratum-a".into()],
        escalation_witness_strata: vec!["stratum-a".into()],
        observer_rounds: 0,
        observer_committee_size: 0,
        max_reassignment_depth: 0,
        max_checkpoint_staleness_ms: 120_000,
        observer_correlation_budget: AsymptoteObserverCorrelationBudget::default(),
        observer_sealing_mode: AsymptoteObserverSealingMode::SampledCloseV1,
        observer_challenge_window_ms: 0,
    };
    let mut parent_view = build_parent_view_with_bulletin_commitment(
        &manifest,
        &[build_log_descriptor(
            &manifest.transparency_log_id,
            &log_keypair,
        )],
        policy,
        GuardianWitnessEpochSeed {
            epoch: manifest.epoch,
            seed: [142u8; 32],
            checkpoint_interval_blocks: 4,
            max_reassignment_depth: 0,
        },
        &[header
            .guardian_certificate
            .as_ref()
            .unwrap()
            .log_checkpoint
            .clone()
            .unwrap()],
        bulletin,
    );
    let previous =
        test_canonical_collapse_object(header.height - 1, None, [212u8; 32], [213u8; 32]);
    parent_view.state.insert(
        aft_canonical_collapse_object_key(previous.height),
        codec::to_bytes_canonical(&previous).unwrap(),
    );
    let mut collapse =
        derive_canonical_collapse_object_with_previous(&header, &[], Some(&previous)).unwrap();
    collapse.resulting_state_root_hash = [143u8; 32];
    parent_view.state.insert(
        aft_canonical_collapse_object_key(header.height),
        codec::to_bytes_canonical(&collapse).unwrap(),
    );

    let err = engine
        .verify_published_canonical_collapse_object(&header, &parent_view)
        .await
        .unwrap_err();
    assert!(err
        .to_string()
        .contains("published canonical collapse object does not match"));
}

#[tokio::test]
async fn asymptote_rejects_valid_equal_authority_veto_proof() {
    let (mut engine, mut header, manifest, preimage, _, guardian_log_keypair) =
        build_case(&[(0, 0), (1, 1)]);
    engine.safety_mode = AftSafetyMode::Asymptote;
    let guardian_log_descriptor =
        build_log_descriptor(&manifest.transparency_log_id, &guardian_log_keypair);
    let witness_seed = GuardianWitnessEpochSeed {
        epoch: manifest.epoch,
        seed: [92u8; 32],
        checkpoint_interval_blocks: 1,
        max_reassignment_depth: 0,
    };
    let policy = AsymptotePolicy {
        epoch: manifest.epoch,
        high_risk_effect_tier: FinalityTier::SealedFinal,
        required_witness_strata: Vec::new(),
        escalation_witness_strata: Vec::new(),
        observer_rounds: 1,
        observer_committee_size: 1,
        observer_correlation_budget: AsymptoteObserverCorrelationBudget::default(),
        observer_sealing_mode: AsymptoteObserverSealingMode::SampledCloseV1,
        observer_challenge_window_ms: 0,
        max_reassignment_depth: 0,
        max_checkpoint_staleness_ms: 120_000,
    };
    let validators = vec![
        header.producer_account_id,
        AccountId([41u8; 32]),
        AccountId([42u8; 32]),
    ];
    let assignment = derive_asymptote_observer_assignments(
        &witness_seed,
        &build_validator_sets(validators.clone()).current,
        header.producer_account_id,
        header.height,
        header.view,
        policy.observer_rounds,
        policy.observer_committee_size,
    )
    .unwrap()
    .into_iter()
    .next()
    .unwrap();
    let observer_assignments_hash =
        canonical_asymptote_observer_assignments_hash(std::slice::from_ref(&assignment)).unwrap();
    let mut observer_manifests = Vec::new();
    let mut selected_manifest = None;
    let mut selected_member_keys = None;
    for account in validators
        .iter()
        .copied()
        .filter(|account| *account != header.producer_account_id)
    {
        let member_keys = vec![
            BlsKeyPair::generate().unwrap(),
            BlsKeyPair::generate().unwrap(),
            BlsKeyPair::generate().unwrap(),
        ];
        let observer_manifest = build_observer_manifest(
            account,
            manifest.epoch,
            [62u8; 32],
            &format!("observer-veto-{}", hex::encode(account.as_ref())),
            &member_keys,
        );
        if account == assignment.observer_account_id {
            selected_manifest = Some(observer_manifest.clone());
            selected_member_keys = Some(member_keys);
        }
        observer_manifests.push(observer_manifest);
    }
    let observer_manifest = selected_manifest.unwrap();
    let member_keys = selected_member_keys.unwrap();
    let provisional = AsymptoteObserverCertificate {
        assignment: assignment.clone(),
        verdict: AsymptoteObserverVerdict::Veto,
        veto_kind: Some(AsymptoteVetoKind::ConflictingGuardianCertificate),
        evidence_hash: [7u8; 32],
        guardian_certificate: GuardianQuorumCertificate::default(),
    };
    let base_certificate = header.guardian_certificate.as_ref().unwrap().clone();
    let statement = engine
        .asymptote_observer_statement(&header, &base_certificate, &provisional)
        .unwrap();
    let decision = GuardianDecision {
        domain: GuardianDecisionDomain::AsymptoteObserve as u8,
        subject: assignment.observer_account_id.0.to_vec(),
        payload_hash: ioi_crypto::algorithms::hash::sha256(
            &codec::to_bytes_canonical(&statement).unwrap(),
        )
        .unwrap(),
        counter: 1,
        trace_hash: [4u8; 32],
        measurement_root: observer_manifest.measurement_profile_root,
        policy_hash: observer_manifest.policy_hash,
    };
    let observer_log_keypair = Keypair::generate_ed25519();
    let mut observer_guardian_certificate = sign_decision_with_members(
        &observer_manifest,
        &decision,
        decision.counter,
        decision.trace_hash,
        &[
            (0, member_keys[0].private_key()),
            (1, member_keys[1].private_key()),
        ],
    )
    .unwrap();
    let checkpoint_entry =
        codec::to_bytes_canonical(&(decision.clone(), observer_guardian_certificate.clone()))
            .unwrap();
    observer_guardian_certificate.log_checkpoint = Some(build_signed_checkpoint(
        &observer_manifest.transparency_log_id,
        &observer_log_keypair,
        &[checkpoint_entry],
        0,
        1,
    ));
    let veto_proof = AsymptoteVetoProof {
        observer_certificate: AsymptoteObserverCertificate {
            assignment,
            verdict: AsymptoteObserverVerdict::Veto,
            veto_kind: Some(AsymptoteVetoKind::ConflictingGuardianCertificate),
            evidence_hash: [7u8; 32],
            guardian_certificate: observer_guardian_certificate.clone(),
        },
        details: "conflicting guardian-backed slot evidence".into(),
    };
    let anchored_checkpoints = vec![
        base_certificate.log_checkpoint.as_ref().unwrap().clone(),
        observer_guardian_certificate
            .log_checkpoint
            .as_ref()
            .unwrap()
            .clone(),
    ];

    header.sealed_finality_proof = Some(SealedFinalityProof {
        epoch: manifest.epoch,
        finality_tier: FinalityTier::SealedFinal,
        collapse_state: CollapseState::SealedFinal,
        guardian_manifest_hash: base_certificate.manifest_hash,
        guardian_decision_hash: base_certificate.decision_hash,
        guardian_counter: base_certificate.counter,
        guardian_trace_hash: base_certificate.trace_hash,
        guardian_measurement_root: base_certificate.measurement_root,
        policy_hash: manifest.policy_hash,
        witness_certificates: Vec::new(),
        observer_certificates: Vec::new(),
        observer_close_certificate: Some(AsymptoteObserverCloseCertificate {
            epoch: manifest.epoch,
            height: header.height,
            view: header.view,
            assignments_hash: observer_assignments_hash,
            expected_assignments: 1,
            ok_count: 0,
            veto_count: 1,
        }),
        observer_transcripts: Vec::new(),
        observer_challenges: Vec::new(),
        observer_transcript_commitment: None,
        observer_challenge_commitment: None,
        observer_canonical_close: None,
        observer_canonical_abort: None,
        veto_proofs: vec![veto_proof],
        divergence_signals: Vec::new(),
        proof_signature: SignatureProof::default(),
    });
    sign_test_sealed_finality_proof(
        header.sealed_finality_proof.as_mut().unwrap(),
        &guardian_log_keypair,
    );

    let parent_view = build_parent_view_with_asymptote_observers(
        &manifest,
        &[
            guardian_log_descriptor,
            build_log_descriptor(
                &observer_manifest.transparency_log_id,
                &observer_log_keypair,
            ),
        ],
        policy,
        witness_seed,
        &anchored_checkpoints,
        validators,
        &observer_manifests,
    );

    let err = engine
        .verify_guardianized_certificate(&header, &preimage, &parent_view)
        .await
        .unwrap_err();
    assert!(matches!(err, ConsensusError::BlockVerificationFailed(_)));
}

#[tokio::test]
async fn guardian_majority_rejects_checkpoint_log_id_mismatch() {
    let (engine, mut header, manifest, preimage, _, guardian_log_keypair) =
        build_case(&[(0, 0), (1, 1)]);
    header.guardian_certificate.as_mut().unwrap().log_checkpoint = Some(GuardianLogCheckpoint {
        log_id: "wrong-log".into(),
        tree_size: 1,
        root_hash: [11u8; 32],
        timestamp_ms: 11,
        signature: vec![1],
        proof: None,
    });
    let parent_view = build_parent_view(
        &manifest,
        &[build_log_descriptor(
            &manifest.transparency_log_id,
            &guardian_log_keypair,
        )],
        &[],
        GuardianWitnessSet::default(),
        GuardianWitnessEpochSeed::default(),
        &[],
    );

    let err = engine
        .verify_guardianized_certificate(&header, &preimage, &parent_view)
        .await
        .unwrap_err();
    assert!(matches!(err, ConsensusError::BlockVerificationFailed(_)));
}

#[tokio::test]
async fn guardian_majority_rejects_checkpoint_rollback_against_anchor() {
    let (engine, header, manifest, preimage, _, guardian_log_keypair) =
        build_case(&[(0, 0), (1, 1)]);
    let guardian_entry = codec::to_bytes_canonical(&(
        GuardianDecision {
            domain: GuardianDecisionDomain::ConsensusSlot as u8,
            subject: manifest.validator_account_id.0.to_vec(),
            payload_hash: ioi_crypto::algorithms::hash::sha256(&preimage).unwrap(),
            counter: header.oracle_counter,
            trace_hash: header.oracle_trace_hash,
            measurement_root: manifest.measurement_profile_root,
            policy_hash: manifest.policy_hash,
        },
        {
            let mut checkpoint_certificate = header.guardian_certificate.as_ref().unwrap().clone();
            checkpoint_certificate.log_checkpoint = None;
            checkpoint_certificate.experimental_witness_certificate = None;
            checkpoint_certificate
        },
    ))
    .unwrap();
    let parent_view = build_parent_view(
        &manifest,
        &[build_log_descriptor(
            &manifest.transparency_log_id,
            &guardian_log_keypair,
        )],
        &[],
        GuardianWitnessSet::default(),
        GuardianWitnessEpochSeed::default(),
        &[build_signed_checkpoint(
            &manifest.transparency_log_id,
            &guardian_log_keypair,
            &[guardian_entry.clone(), b"anchor-2".to_vec()],
            1,
            20,
        )],
    );

    let err = engine
        .verify_guardianized_certificate(&header, &preimage, &parent_view)
        .await
        .unwrap_err();
    assert!(matches!(err, ConsensusError::BlockVerificationFailed(_)));
}

#[tokio::test]
async fn experimental_nested_guardian_rejects_witness_checkpoint_rollback_against_anchor() {
    let (mut engine, mut header, manifest, preimage, _, guardian_log_keypair) =
        build_case(&[(0, 0), (1, 1)]);
    engine.safety_mode = AftSafetyMode::ExperimentalNestedGuardian;
    let guardian_log_descriptor =
        build_log_descriptor(&manifest.transparency_log_id, &guardian_log_keypair);
    let witness_log_keypair = Keypair::generate_ed25519();

    let witness_members = vec![
        BlsKeyPair::generate().unwrap(),
        BlsKeyPair::generate().unwrap(),
        BlsKeyPair::generate().unwrap(),
        BlsKeyPair::generate().unwrap(),
    ];
    let witness_manifest = build_witness_manifest(&witness_members);
    let witness_hash = canonical_witness_manifest_hash(&witness_manifest).unwrap();
    let witness_set = GuardianWitnessSet {
        epoch: witness_manifest.epoch,
        manifest_hashes: vec![witness_hash],
        checkpoint_interval_blocks: 1,
    };
    let witness_seed = GuardianWitnessEpochSeed {
        epoch: witness_manifest.epoch,
        seed: [42u8; 32],
        checkpoint_interval_blocks: 1,
        max_reassignment_depth: 1,
    };
    let statement = engine
        .experimental_witness_statement(&header, header.guardian_certificate.as_ref().unwrap());
    let mut witness_certificate = sign_witness_statement_with_members(
        &witness_manifest,
        &statement,
        &[
            (0, witness_members[0].private_key()),
            (1, witness_members[1].private_key()),
            (2, witness_members[2].private_key()),
        ],
    )
    .unwrap();
    let witness_checkpoint_entry =
        codec::to_bytes_canonical(&(statement.clone(), witness_certificate.clone())).unwrap();
    witness_certificate.log_checkpoint = Some(build_signed_checkpoint(
        &witness_manifest.transparency_log_id,
        &witness_log_keypair,
        std::slice::from_ref(&witness_checkpoint_entry),
        0,
        10,
    ));
    header
        .guardian_certificate
        .as_mut()
        .unwrap()
        .experimental_witness_certificate = Some(witness_certificate);
    let parent_view = build_parent_view(
        &manifest,
        &[
            guardian_log_descriptor,
            build_log_descriptor(&witness_manifest.transparency_log_id, &witness_log_keypair),
        ],
        &[witness_manifest.clone()],
        witness_set,
        witness_seed,
        &[
            header
                .guardian_certificate
                .as_ref()
                .unwrap()
                .log_checkpoint
                .as_ref()
                .unwrap()
                .clone(),
            GuardianLogCheckpoint {
                ..build_signed_checkpoint(
                    &witness_manifest.transparency_log_id,
                    &witness_log_keypair,
                    &[witness_checkpoint_entry, b"witness-anchor-2".to_vec()],
                    1,
                    20,
                )
            },
        ],
    );

    let err = engine
        .verify_guardianized_certificate(&header, &preimage, &parent_view)
        .await
        .unwrap_err();
    assert!(matches!(err, ConsensusError::BlockVerificationFailed(_)));
}

#[test]
fn reset_promotes_unique_quorum_candidate_for_committed_height() {
    let mut engine = GuardianMajorityEngine::new(AftSafetyMode::GuardianMajority);
    let block_hash = [9u8; 32];
    engine.remember_validator_count(5, 4);
    engine.vote_pool.insert(
        5,
        HashMap::from([(
            block_hash,
            vec![
                ConsensusVote {
                    height: 5,
                    view: 0,
                    block_hash,
                    voter: AccountId([1u8; 32]),
                    signature: vec![1u8],
                },
                ConsensusVote {
                    height: 5,
                    view: 0,
                    block_hash,
                    voter: AccountId([2u8; 32]),
                    signature: vec![2u8],
                },
                ConsensusVote {
                    height: 5,
                    view: 0,
                    block_hash,
                    voter: AccountId([3u8; 32]),
                    signature: vec![3u8],
                },
            ],
        )]),
    );

    <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::reset(&mut engine, 5);

    assert_eq!(engine.highest_qc.height, 5);
    assert_eq!(engine.highest_qc.block_hash, block_hash);
    assert_eq!(
            <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::take_pending_quorum_certificates(
                &mut engine,
            )
            .len(),
            1
        );
}

#[test]
fn asymptote_reset_does_not_promote_vote_only_quorum_candidate_for_committed_height() {
    let mut engine = GuardianMajorityEngine::new(AftSafetyMode::Asymptote);
    let block_hash = [19u8; 32];
    engine.remember_validator_count(5, 4);
    engine.vote_pool.insert(
        5,
        HashMap::from([(
            block_hash,
            vec![
                ConsensusVote {
                    height: 5,
                    view: 0,
                    block_hash,
                    voter: AccountId([1u8; 32]),
                    signature: vec![1u8],
                },
                ConsensusVote {
                    height: 5,
                    view: 0,
                    block_hash,
                    voter: AccountId([2u8; 32]),
                    signature: vec![2u8],
                },
                ConsensusVote {
                    height: 5,
                    view: 0,
                    block_hash,
                    voter: AccountId([3u8; 32]),
                    signature: vec![3u8],
                },
            ],
        )]),
    );

    <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::reset(&mut engine, 5);

    assert!(engine.highest_qc.height < 5);
    assert!(
            <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::take_pending_quorum_certificates(
                &mut engine,
            )
            .is_empty()
        );
}

#[test]
fn reset_promotes_recovered_header_for_committed_height() {
    let mut engine = GuardianMajorityEngine::new(AftSafetyMode::GuardianMajority);
    let recovered_header = RecoveredCanonicalHeaderEntry {
        height: 5,
        view: 2,
        canonical_block_commitment_hash: [0x45u8; 32],
        parent_block_commitment_hash: [0x34u8; 32],
        transactions_root_hash: [0x23u8; 32],
        resulting_state_root_hash: [0x13u8; 32],
        previous_canonical_collapse_commitment_hash: [0x12u8; 32],
    };

    assert!(<GuardianMajorityEngine as ConsensusEngine<
        ChainTransaction,
    >>::observe_recovered_consensus_header(
        &mut engine,
        &recovered_header,
    ));

    <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::reset(&mut engine, 5);

    assert_eq!(engine.highest_qc.height, 5);
    assert_eq!(engine.highest_qc.view, recovered_header.view);
    assert_eq!(
        engine.highest_qc.block_hash,
        recovered_header.canonical_block_commitment_hash
    );
}

#[test]
fn synthetic_parent_qc_uses_recovered_header_hint() {
    let mut engine = GuardianMajorityEngine::new(AftSafetyMode::GuardianMajority);
    let recovered_header = RecoveredCanonicalHeaderEntry {
        height: 4,
        view: 7,
        canonical_block_commitment_hash: [0x56u8; 32],
        parent_block_commitment_hash: [0x46u8; 32],
        transactions_root_hash: [0x36u8; 32],
        resulting_state_root_hash: [0x26u8; 32],
        previous_canonical_collapse_commitment_hash: [0x26u8; 32],
    };

    assert!(<GuardianMajorityEngine as ConsensusEngine<
        ChainTransaction,
    >>::observe_recovered_consensus_header(
        &mut engine,
        &recovered_header,
    ));

    let parent_qc = engine
        .synthetic_parent_qc_for_height(5)
        .expect("recovered parent QC hint");
    assert_eq!(parent_qc.height, 4);
    assert_eq!(parent_qc.view, recovered_header.view);
    assert_eq!(
        parent_qc.block_hash,
        recovered_header.canonical_block_commitment_hash
    );
}

#[test]
fn recovered_header_for_quorum_certificate_returns_restart_hint() {
    let mut engine = GuardianMajorityEngine::new(AftSafetyMode::GuardianMajority);
    let recovered_header = RecoveredCanonicalHeaderEntry {
        height: 6,
        view: 3,
        canonical_block_commitment_hash: [0x66u8; 32],
        parent_block_commitment_hash: [0x56u8; 32],
        transactions_root_hash: [0x46u8; 32],
        resulting_state_root_hash: [0x36u8; 32],
        previous_canonical_collapse_commitment_hash: [0x26u8; 32],
    };

    assert!(<GuardianMajorityEngine as ConsensusEngine<
        ChainTransaction,
    >>::observe_recovered_consensus_header(
        &mut engine,
        &recovered_header,
    ));

    let recovered_qc = recovered_header.synthetic_quorum_certificate();
    let resolved = <GuardianMajorityEngine as ConsensusEngine<
            ChainTransaction,
        >>::recovered_consensus_header_for_quorum_certificate(
            &engine,
            &recovered_qc,
        )
        .expect("matching recovered header hint");
    assert_eq!(resolved, recovered_header);
}

#[test]
fn recovered_certified_header_for_quorum_certificate_returns_restart_entry() {
    let mut engine = GuardianMajorityEngine::new(AftSafetyMode::GuardianMajority);
    let previous_header = RecoveredCanonicalHeaderEntry {
        height: 5,
        view: 2,
        canonical_block_commitment_hash: [0x55u8; 32],
        parent_block_commitment_hash: [0x45u8; 32],
        transactions_root_hash: [0x35u8; 32],
        resulting_state_root_hash: [0x25u8; 32],
        previous_canonical_collapse_commitment_hash: [0x15u8; 32],
    };
    assert!(<GuardianMajorityEngine as ConsensusEngine<
        ChainTransaction,
    >>::observe_recovered_consensus_header(
        &mut engine,
        &previous_header,
    ));

    let recovered_entry = RecoveredCertifiedHeaderEntry {
        header: RecoveredCanonicalHeaderEntry {
            height: 6,
            view: 3,
            canonical_block_commitment_hash: [0x66u8; 32],
            parent_block_commitment_hash: previous_header.canonical_block_commitment_hash,
            transactions_root_hash: [0x46u8; 32],
            resulting_state_root_hash: [0x36u8; 32],
            previous_canonical_collapse_commitment_hash: [0x26u8; 32],
        },
        certified_parent_quorum_certificate: previous_header.synthetic_quorum_certificate(),
        certified_parent_resulting_state_root_hash: previous_header.resulting_state_root_hash,
    };

    assert!(<GuardianMajorityEngine as ConsensusEngine<
        ChainTransaction,
    >>::observe_recovered_certified_header(
        &mut engine,
        &recovered_entry,
    ));

    let resolved = <GuardianMajorityEngine as ConsensusEngine<
            ChainTransaction,
        >>::recovered_certified_header_for_quorum_certificate(
            &engine,
            &recovered_entry.certified_quorum_certificate(),
        )
        .expect("matching recovered certified header hint");
    assert_eq!(resolved, recovered_entry);
}

#[test]
fn observe_recovered_certified_header_rejects_conflicting_parent_state_root() {
    let mut engine = GuardianMajorityEngine::new(AftSafetyMode::GuardianMajority);
    let previous_header = RecoveredCanonicalHeaderEntry {
        height: 7,
        view: 4,
        canonical_block_commitment_hash: [0x77u8; 32],
        parent_block_commitment_hash: [0x67u8; 32],
        transactions_root_hash: [0x57u8; 32],
        resulting_state_root_hash: [0x47u8; 32],
        previous_canonical_collapse_commitment_hash: [0x37u8; 32],
    };
    assert!(<GuardianMajorityEngine as ConsensusEngine<
        ChainTransaction,
    >>::observe_recovered_consensus_header(
        &mut engine,
        &previous_header,
    ));

    let conflicting_entry = RecoveredCertifiedHeaderEntry {
        header: RecoveredCanonicalHeaderEntry {
            height: 8,
            view: 5,
            canonical_block_commitment_hash: [0x88u8; 32],
            parent_block_commitment_hash: previous_header.canonical_block_commitment_hash,
            transactions_root_hash: [0x68u8; 32],
            resulting_state_root_hash: [0x58u8; 32],
            previous_canonical_collapse_commitment_hash: [0x48u8; 32],
        },
        certified_parent_quorum_certificate: previous_header.synthetic_quorum_certificate(),
        certified_parent_resulting_state_root_hash: [0xffu8; 32],
    };

    assert!(!<GuardianMajorityEngine as ConsensusEngine<
        ChainTransaction,
    >>::observe_recovered_certified_header(
        &mut engine,
        &conflicting_entry,
    ));
}

#[test]
fn header_for_quorum_certificate_returns_recovered_restart_header() {
    let mut engine = GuardianMajorityEngine::new(AftSafetyMode::GuardianMajority);
    let previous_header = RecoveredCanonicalHeaderEntry {
        height: 6,
        view: 2,
        canonical_block_commitment_hash: [0x61u8; 32],
        parent_block_commitment_hash: [0x51u8; 32],
        transactions_root_hash: [0x41u8; 32],
        resulting_state_root_hash: [0x31u8; 32],
        previous_canonical_collapse_commitment_hash: [0x21u8; 32],
    };
    assert!(<GuardianMajorityEngine as ConsensusEngine<
        ChainTransaction,
    >>::observe_recovered_consensus_header(
        &mut engine,
        &previous_header,
    ));

    let certified_entry = RecoveredCertifiedHeaderEntry {
        header: RecoveredCanonicalHeaderEntry {
            height: 7,
            view: 3,
            canonical_block_commitment_hash: [0x71u8; 32],
            parent_block_commitment_hash: previous_header.canonical_block_commitment_hash,
            transactions_root_hash: [0x51u8; 32],
            resulting_state_root_hash: [0x41u8; 32],
            previous_canonical_collapse_commitment_hash: [0x31u8; 32],
        },
        certified_parent_quorum_certificate: previous_header.synthetic_quorum_certificate(),
        certified_parent_resulting_state_root_hash: previous_header.resulting_state_root_hash,
    };
    let payload = RecoverableSlotPayloadV5 {
        height: 7,
        view: 3,
        producer_account_id: AccountId([0x72u8; 32]),
        block_commitment_hash: certified_entry.header.canonical_block_commitment_hash,
        parent_block_hash: certified_entry.header.parent_block_commitment_hash,
        canonical_order_certificate: CanonicalOrderCertificate {
            height: 7,
            bulletin_commitment: BulletinCommitment {
                height: 7,
                cutoff_timestamp_ms: 1_760_000_777_000,
                bulletin_root: [0x73u8; 32],
                entry_count: 0,
            },
            bulletin_availability_certificate: BulletinAvailabilityCertificate {
                height: 7,
                bulletin_commitment_hash: [0x74u8; 32],
                recoverability_root: [0x75u8; 32],
            },
            randomness_beacon: [0x76u8; 32],
            ordered_transactions_root_hash: certified_entry.header.transactions_root_hash,
            resulting_state_root_hash: certified_entry.header.resulting_state_root_hash,
            proof: CanonicalOrderProof::default(),
            omission_proofs: Vec::new(),
        },
        ordered_transaction_bytes: Vec::new(),
        canonical_order_publication_bundle_bytes: Vec::new(),
        canonical_bulletin_close_bytes: Vec::new(),
        canonical_bulletin_availability_certificate_bytes: Vec::new(),
        bulletin_surface_entries: Vec::new(),
    };
    let restart_entry =
        recovered_restart_block_header_entry(&payload, &certified_entry).expect("restart entry");

    assert!(<GuardianMajorityEngine as ConsensusEngine<
        ChainTransaction,
    >>::observe_recovered_restart_block_header(
        &mut engine,
        &restart_entry,
    ));

    let resolved = <GuardianMajorityEngine as ConsensusEngine<
            ChainTransaction,
        >>::header_for_quorum_certificate(
            &engine,
            &restart_entry.certified_quorum_certificate(),
        )
        .expect("matching recovered restart header");
    assert_eq!(resolved, restart_entry.header);
}

#[test]
fn observe_recovered_restart_block_header_rejects_conflicting_parent_qc() {
    let mut engine = GuardianMajorityEngine::new(AftSafetyMode::GuardianMajority);
    let previous_header = RecoveredCanonicalHeaderEntry {
        height: 8,
        view: 4,
        canonical_block_commitment_hash: [0x81u8; 32],
        parent_block_commitment_hash: [0x71u8; 32],
        transactions_root_hash: [0x61u8; 32],
        resulting_state_root_hash: [0x51u8; 32],
        previous_canonical_collapse_commitment_hash: [0x41u8; 32],
    };
    assert!(<GuardianMajorityEngine as ConsensusEngine<
        ChainTransaction,
    >>::observe_recovered_consensus_header(
        &mut engine,
        &previous_header,
    ));

    let certified_entry = RecoveredCertifiedHeaderEntry {
        header: RecoveredCanonicalHeaderEntry {
            height: 9,
            view: 5,
            canonical_block_commitment_hash: [0x91u8; 32],
            parent_block_commitment_hash: previous_header.canonical_block_commitment_hash,
            transactions_root_hash: [0x71u8; 32],
            resulting_state_root_hash: [0x61u8; 32],
            previous_canonical_collapse_commitment_hash: [0x51u8; 32],
        },
        certified_parent_quorum_certificate: previous_header.synthetic_quorum_certificate(),
        certified_parent_resulting_state_root_hash: previous_header.resulting_state_root_hash,
    };
    let payload = RecoverableSlotPayloadV5 {
        height: 9,
        view: 5,
        producer_account_id: AccountId([0x92u8; 32]),
        block_commitment_hash: certified_entry.header.canonical_block_commitment_hash,
        parent_block_hash: certified_entry.header.parent_block_commitment_hash,
        canonical_order_certificate: CanonicalOrderCertificate {
            height: 9,
            bulletin_commitment: BulletinCommitment {
                height: 9,
                cutoff_timestamp_ms: 1_760_000_999_000,
                bulletin_root: [0x93u8; 32],
                entry_count: 0,
            },
            bulletin_availability_certificate: BulletinAvailabilityCertificate {
                height: 9,
                bulletin_commitment_hash: [0x94u8; 32],
                recoverability_root: [0x95u8; 32],
            },
            randomness_beacon: [0x96u8; 32],
            ordered_transactions_root_hash: certified_entry.header.transactions_root_hash,
            resulting_state_root_hash: certified_entry.header.resulting_state_root_hash,
            proof: CanonicalOrderProof::default(),
            omission_proofs: Vec::new(),
        },
        ordered_transaction_bytes: Vec::new(),
        canonical_order_publication_bundle_bytes: Vec::new(),
        canonical_bulletin_close_bytes: Vec::new(),
        canonical_bulletin_availability_certificate_bytes: Vec::new(),
        bulletin_surface_entries: Vec::new(),
    };
    let mut restart_entry =
        recovered_restart_block_header_entry(&payload, &certified_entry).expect("restart entry");
    restart_entry.header.parent_qc.block_hash[0] ^= 0xFF;

    assert!(!<GuardianMajorityEngine as ConsensusEngine<
        ChainTransaction,
    >>::observe_recovered_restart_block_header(
        &mut engine,
        &restart_entry,
    ));
}

#[test]
fn aft_recovered_trait_paths_match_legacy_wrappers() {
    let previous_header = RecoveredCanonicalHeaderEntry {
        height: 5,
        view: 2,
        canonical_block_commitment_hash: [0x51u8; 32],
        parent_block_commitment_hash: [0x41u8; 32],
        transactions_root_hash: [0x31u8; 32],
        resulting_state_root_hash: [0x21u8; 32],
        previous_canonical_collapse_commitment_hash: [0x11u8; 32],
    };
    let certified_entry = RecoveredCertifiedHeaderEntry {
        header: RecoveredCanonicalHeaderEntry {
            height: 6,
            view: 3,
            canonical_block_commitment_hash: [0x61u8; 32],
            parent_block_commitment_hash: previous_header.canonical_block_commitment_hash,
            transactions_root_hash: [0x41u8; 32],
            resulting_state_root_hash: [0x31u8; 32],
            previous_canonical_collapse_commitment_hash: [0x21u8; 32],
        },
        certified_parent_quorum_certificate: previous_header.synthetic_quorum_certificate(),
        certified_parent_resulting_state_root_hash: previous_header.resulting_state_root_hash,
    };
    let restart_entry = sample_recovered_restart_entry(
        &certified_entry.header,
        certified_entry.certified_quorum_certificate(),
        certified_entry.header.resulting_state_root_hash,
        7,
        4,
        0x71,
        0x72,
        0x73,
        0x74,
        0x75,
        0x76,
    );

    let mut legacy_engine = GuardianMajorityEngine::new(AftSafetyMode::GuardianMajority);
    let mut aft_engine = GuardianMajorityEngine::new(AftSafetyMode::GuardianMajority);

    assert!(<GuardianMajorityEngine as ConsensusEngine<
        ChainTransaction,
    >>::observe_recovered_consensus_header(
        &mut legacy_engine,
        &previous_header,
    ));
    assert!(<GuardianMajorityEngine as ConsensusEngine<
        ChainTransaction,
    >>::observe_recovered_certified_header(
        &mut legacy_engine,
        &certified_entry,
    ));
    assert!(<GuardianMajorityEngine as ConsensusEngine<
        ChainTransaction,
    >>::observe_recovered_restart_block_header(
        &mut legacy_engine,
        &restart_entry,
    ));

    assert!(<GuardianMajorityEngine as ConsensusEngine<
        ChainTransaction,
    >>::observe_aft_recovered_consensus_header(
        &mut aft_engine,
        &previous_header,
    ));
    assert!(<GuardianMajorityEngine as ConsensusEngine<
        ChainTransaction,
    >>::observe_aft_recovered_certified_header(
        &mut aft_engine,
        &certified_entry,
    ));
    assert!(<GuardianMajorityEngine as ConsensusEngine<
        ChainTransaction,
    >>::observe_aft_recovered_restart_header(
        &mut aft_engine,
        &restart_entry,
    ));

    assert_eq!(
        legacy_engine.recovered_headers,
        aft_engine.recovered_headers
    );
    assert_eq!(
        legacy_engine.recovered_certified_headers,
        aft_engine.recovered_certified_headers
    );
    assert_eq!(
        legacy_engine.recovered_restart_headers,
        aft_engine.recovered_restart_headers
    );

    let recovered_qc = previous_header.synthetic_quorum_certificate();
    let certified_qc = certified_entry.certified_quorum_certificate();
    let restart_qc = restart_entry.certified_quorum_certificate();
    assert_eq!(
            <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::recovered_consensus_header_for_quorum_certificate(
                &legacy_engine,
                &recovered_qc,
            ),
            <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::aft_recovered_consensus_header_for_quorum_certificate(
                &aft_engine,
                &recovered_qc,
            )
        );
    assert_eq!(
            <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::recovered_certified_header_for_quorum_certificate(
                &legacy_engine,
                &certified_qc,
            ),
            <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::aft_recovered_certified_header_for_quorum_certificate(
                &aft_engine,
                &certified_qc,
            )
        );
    assert_eq!(
            <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::recovered_restart_block_header_for_quorum_certificate(
                &legacy_engine,
                &restart_qc,
            ),
            <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::aft_recovered_restart_header_for_quorum_certificate(
                &aft_engine,
                &restart_qc,
            )
        );
}

#[test]
fn observe_aft_recovered_state_surface_matches_manual_header_seeding() {
    let previous_header = RecoveredCanonicalHeaderEntry {
        height: 5,
        view: 2,
        canonical_block_commitment_hash: [0x51u8; 32],
        parent_block_commitment_hash: [0x41u8; 32],
        transactions_root_hash: [0x31u8; 32],
        resulting_state_root_hash: [0x21u8; 32],
        previous_canonical_collapse_commitment_hash: [0x11u8; 32],
    };
    let certified_entry = RecoveredCertifiedHeaderEntry {
        header: RecoveredCanonicalHeaderEntry {
            height: 6,
            view: 3,
            canonical_block_commitment_hash: [0x61u8; 32],
            parent_block_commitment_hash: previous_header.canonical_block_commitment_hash,
            transactions_root_hash: [0x41u8; 32],
            resulting_state_root_hash: [0x31u8; 32],
            previous_canonical_collapse_commitment_hash: [0x21u8; 32],
        },
        certified_parent_quorum_certificate: previous_header.synthetic_quorum_certificate(),
        certified_parent_resulting_state_root_hash: previous_header.resulting_state_root_hash,
    };
    let restart_entry = sample_recovered_restart_entry(
        &certified_entry.header,
        certified_entry.certified_quorum_certificate(),
        certified_entry.header.resulting_state_root_hash,
        7,
        4,
        0x71,
        0x72,
        0x73,
        0x74,
        0x75,
        0x76,
    );
    let surface = AftRecoveredStateSurface {
        replay_prefix: Vec::new(),
        consensus_headers: vec![previous_header.clone()],
        certified_headers: vec![certified_entry.clone()],
        restart_headers: vec![restart_entry.clone()],
        historical_retrievability: None,
    };

    let mut manual_engine = GuardianMajorityEngine::new(AftSafetyMode::GuardianMajority);
    let mut surface_engine = GuardianMajorityEngine::new(AftSafetyMode::GuardianMajority);

    assert!(<GuardianMajorityEngine as ConsensusEngine<
        ChainTransaction,
    >>::observe_aft_recovered_consensus_header(
        &mut manual_engine,
        &previous_header,
    ));
    assert!(<GuardianMajorityEngine as ConsensusEngine<
        ChainTransaction,
    >>::observe_aft_recovered_certified_header(
        &mut manual_engine,
        &certified_entry,
    ));
    assert!(<GuardianMajorityEngine as ConsensusEngine<
        ChainTransaction,
    >>::observe_aft_recovered_restart_header(
        &mut manual_engine,
        &restart_entry,
    ));

    let stats = <GuardianMajorityEngine as ConsensusEngine<
            ChainTransaction,
        >>::observe_aft_recovered_state_surface(&mut surface_engine, &surface);

    assert_eq!(stats.accepted_consensus_headers, 1);
    assert_eq!(stats.accepted_certified_headers, 1);
    assert_eq!(stats.accepted_restart_headers, 1);
    assert!(stats.accepted_any());

    assert_eq!(
        manual_engine.recovered_headers,
        surface_engine.recovered_headers
    );
    assert_eq!(
        manual_engine.recovered_certified_headers,
        surface_engine.recovered_certified_headers
    );
    assert_eq!(
        manual_engine.recovered_restart_headers,
        surface_engine.recovered_restart_headers
    );

    let recovered_qc = previous_header.synthetic_quorum_certificate();
    let certified_qc = certified_entry.certified_quorum_certificate();
    let restart_qc = restart_entry.certified_quorum_certificate();
    assert_eq!(
            <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::aft_recovered_consensus_header_for_quorum_certificate(
                &manual_engine,
                &recovered_qc,
            ),
            <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::aft_recovered_consensus_header_for_quorum_certificate(
                &surface_engine,
                &recovered_qc,
            )
        );
    assert_eq!(
            <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::aft_recovered_certified_header_for_quorum_certificate(
                &manual_engine,
                &certified_qc,
            ),
            <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::aft_recovered_certified_header_for_quorum_certificate(
                &surface_engine,
                &certified_qc,
            )
        );
    assert_eq!(
            <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::aft_recovered_restart_header_for_quorum_certificate(
                &manual_engine,
                &restart_qc,
            ),
            <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::aft_recovered_restart_header_for_quorum_certificate(
                &surface_engine,
                &restart_qc,
            )
        );
}

#[test]
fn recovered_restart_block_header_for_quorum_certificate_returns_later_step_entry() {
    let mut engine = GuardianMajorityEngine::new(AftSafetyMode::GuardianMajority);
    let previous_header = RecoveredCanonicalHeaderEntry {
        height: 10,
        view: 5,
        canonical_block_commitment_hash: [0xA1u8; 32],
        parent_block_commitment_hash: [0x91u8; 32],
        transactions_root_hash: [0x81u8; 32],
        resulting_state_root_hash: [0x71u8; 32],
        previous_canonical_collapse_commitment_hash: [0x61u8; 32],
    };
    assert!(<GuardianMajorityEngine as ConsensusEngine<
        ChainTransaction,
    >>::observe_recovered_consensus_header(
        &mut engine,
        &previous_header,
    ));

    let step_one = sample_recovered_restart_entry(
        &previous_header,
        previous_header.synthetic_quorum_certificate(),
        previous_header.resulting_state_root_hash,
        11,
        6,
        0xA2,
        0x82,
        0x72,
        0x62,
        0xB2,
        0xC2,
    );
    let step_two = sample_recovered_restart_entry(
        &step_one.certified_header.header,
        step_one.certified_quorum_certificate(),
        step_one.certified_header.header.resulting_state_root_hash,
        12,
        7,
        0xA3,
        0x83,
        0x73,
        0x63,
        0xB3,
        0xC3,
    );
    let step_three = sample_recovered_restart_entry(
        &step_two.certified_header.header,
        step_two.certified_quorum_certificate(),
        step_two.certified_header.header.resulting_state_root_hash,
        13,
        8,
        0xA4,
        0x84,
        0x74,
        0x64,
        0xB4,
        0xC4,
    );

    for entry in [&step_one, &step_two, &step_three] {
        assert!(<GuardianMajorityEngine as ConsensusEngine<
            ChainTransaction,
        >>::observe_recovered_restart_block_header(
            &mut engine, entry,
        ));
    }

    let resolved = <GuardianMajorityEngine as ConsensusEngine<
            ChainTransaction,
        >>::recovered_restart_block_header_for_quorum_certificate(
            &engine,
            &step_three.certified_quorum_certificate(),
        )
        .expect("later-step recovered restart entry");
    assert_eq!(resolved, step_three);

    let resolved_header = <GuardianMajorityEngine as ConsensusEngine<
            ChainTransaction,
        >>::header_for_quorum_certificate(
            &engine,
            &step_three.certified_quorum_certificate(),
        )
        .expect("later-step recovered restart header");
    assert_eq!(resolved_header, step_three.header);
}

#[test]
fn recovered_restart_block_header_for_quorum_certificate_returns_fourth_step_entry() {
    let mut engine = GuardianMajorityEngine::new(AftSafetyMode::GuardianMajority);
    let previous_header = RecoveredCanonicalHeaderEntry {
        height: 20,
        view: 9,
        canonical_block_commitment_hash: [0xB1u8; 32],
        parent_block_commitment_hash: [0xA1u8; 32],
        transactions_root_hash: [0x91u8; 32],
        resulting_state_root_hash: [0x81u8; 32],
        previous_canonical_collapse_commitment_hash: [0x71u8; 32],
    };
    assert!(<GuardianMajorityEngine as ConsensusEngine<
        ChainTransaction,
    >>::observe_recovered_consensus_header(
        &mut engine,
        &previous_header,
    ));

    let step_one = sample_recovered_restart_entry(
        &previous_header,
        previous_header.synthetic_quorum_certificate(),
        previous_header.resulting_state_root_hash,
        21,
        10,
        0xB2,
        0x92,
        0x82,
        0x72,
        0xC2,
        0xD2,
    );
    let step_two = sample_recovered_restart_entry(
        &step_one.certified_header.header,
        step_one.certified_quorum_certificate(),
        step_one.certified_header.header.resulting_state_root_hash,
        22,
        11,
        0xB3,
        0x93,
        0x83,
        0x73,
        0xC3,
        0xD3,
    );
    let step_three = sample_recovered_restart_entry(
        &step_two.certified_header.header,
        step_two.certified_quorum_certificate(),
        step_two.certified_header.header.resulting_state_root_hash,
        23,
        12,
        0xB4,
        0x94,
        0x84,
        0x74,
        0xC4,
        0xD4,
    );
    let step_four = sample_recovered_restart_entry(
        &step_three.certified_header.header,
        step_three.certified_quorum_certificate(),
        step_three.certified_header.header.resulting_state_root_hash,
        24,
        13,
        0xB5,
        0x95,
        0x85,
        0x75,
        0xC5,
        0xD5,
    );

    for entry in [&step_one, &step_two, &step_three, &step_four] {
        assert!(<GuardianMajorityEngine as ConsensusEngine<
            ChainTransaction,
        >>::observe_recovered_restart_block_header(
            &mut engine, entry,
        ));
    }

    let resolved = <GuardianMajorityEngine as ConsensusEngine<
            ChainTransaction,
        >>::recovered_restart_block_header_for_quorum_certificate(
            &engine,
            &step_four.certified_quorum_certificate(),
        )
        .expect("fourth-step recovered restart entry");
    assert_eq!(resolved, step_four);

    let resolved_header = <GuardianMajorityEngine as ConsensusEngine<
            ChainTransaction,
        >>::header_for_quorum_certificate(
            &engine,
            &step_four.certified_quorum_certificate(),
        )
        .expect("fourth-step recovered restart header");
    assert_eq!(resolved_header, step_four.header);
}

#[test]
fn recovered_restart_block_header_for_quorum_certificate_returns_fifth_step_entry() {
    let mut engine = GuardianMajorityEngine::new(AftSafetyMode::GuardianMajority);
    let previous_header = RecoveredCanonicalHeaderEntry {
        height: 30,
        view: 14,
        canonical_block_commitment_hash: [0xC1u8; 32],
        parent_block_commitment_hash: [0xB1u8; 32],
        transactions_root_hash: [0xA1u8; 32],
        resulting_state_root_hash: [0x91u8; 32],
        previous_canonical_collapse_commitment_hash: [0x81u8; 32],
    };
    assert!(<GuardianMajorityEngine as ConsensusEngine<
        ChainTransaction,
    >>::observe_recovered_consensus_header(
        &mut engine,
        &previous_header,
    ));

    let branch = sample_recovered_restart_entry_branch(&previous_header, 15, 5, 0xD1);
    for entry in &branch {
        assert!(<GuardianMajorityEngine as ConsensusEngine<
            ChainTransaction,
        >>::observe_recovered_restart_block_header(
            &mut engine, entry,
        ));
    }

    let tail = branch.last().expect("fifth-step branch tail");
    let resolved = <GuardianMajorityEngine as ConsensusEngine<
            ChainTransaction,
        >>::recovered_restart_block_header_for_quorum_certificate(
            &engine,
            &tail.certified_quorum_certificate(),
        )
        .expect("fifth-step recovered restart entry");
    assert_eq!(resolved, *tail);

    let resolved_header = <GuardianMajorityEngine as ConsensusEngine<
            ChainTransaction,
        >>::header_for_quorum_certificate(
            &engine,
            &tail.certified_quorum_certificate(),
        )
        .expect("fifth-step recovered restart header");
    assert_eq!(resolved_header, tail.header);
}

#[test]
fn retain_recovered_ancestry_ranges_prunes_restart_caches_outside_keep_ranges() {
    let mut engine = GuardianMajorityEngine::new(AftSafetyMode::GuardianMajority);
    let previous_header = RecoveredCanonicalHeaderEntry {
        height: 40,
        view: 19,
        canonical_block_commitment_hash: [0xD1u8; 32],
        parent_block_commitment_hash: [0xC1u8; 32],
        transactions_root_hash: [0xB1u8; 32],
        resulting_state_root_hash: [0xA1u8; 32],
        previous_canonical_collapse_commitment_hash: [0x91u8; 32],
    };
    assert!(<GuardianMajorityEngine as ConsensusEngine<
        ChainTransaction,
    >>::observe_recovered_consensus_header(
        &mut engine,
        &previous_header,
    ));

    let branch = sample_recovered_restart_entry_branch(&previous_header, 20, 5, 0xE1);
    for entry in &branch {
        assert!(<GuardianMajorityEngine as ConsensusEngine<
            ChainTransaction,
        >>::observe_recovered_restart_block_header(
            &mut engine, entry,
        ));
    }

    <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::retain_recovered_ancestry_ranges(
        &mut engine,
        &[(42, 43), (45, 45)],
    );

    let mut recovered_header_heights = engine.recovered_headers.keys().copied().collect::<Vec<_>>();
    let mut recovered_certified_heights = engine
        .recovered_certified_headers
        .keys()
        .copied()
        .collect::<Vec<_>>();
    let mut recovered_restart_heights = engine
        .recovered_restart_headers
        .keys()
        .copied()
        .collect::<Vec<_>>();
    recovered_header_heights.sort_unstable();
    recovered_certified_heights.sort_unstable();
    recovered_restart_heights.sort_unstable();

    assert_eq!(recovered_header_heights, vec![42, 43, 45]);
    assert_eq!(recovered_certified_heights, vec![42, 43, 45]);
    assert_eq!(recovered_restart_heights, vec![42, 43, 45]);
}

#[test]
fn observe_recovered_consensus_header_rejects_conflicting_parent_link() {
    let mut engine = GuardianMajorityEngine::new(AftSafetyMode::GuardianMajority);
    let previous_header = RecoveredCanonicalHeaderEntry {
        height: 4,
        view: 1,
        canonical_block_commitment_hash: [0x61u8; 32],
        parent_block_commitment_hash: [0x51u8; 32],
        transactions_root_hash: [0x41u8; 32],
        resulting_state_root_hash: [0x31u8; 32],
        previous_canonical_collapse_commitment_hash: [0x31u8; 32],
    };
    let conflicting_child = RecoveredCanonicalHeaderEntry {
        height: 5,
        view: 2,
        canonical_block_commitment_hash: [0x62u8; 32],
        parent_block_commitment_hash: [0x99u8; 32],
        transactions_root_hash: [0x42u8; 32],
        resulting_state_root_hash: [0x32u8; 32],
        previous_canonical_collapse_commitment_hash: [0x32u8; 32],
    };

    assert!(<GuardianMajorityEngine as ConsensusEngine<
        ChainTransaction,
    >>::observe_recovered_consensus_header(
        &mut engine,
        &previous_header,
    ));
    assert!(!<GuardianMajorityEngine as ConsensusEngine<
        ChainTransaction,
    >>::observe_recovered_consensus_header(
        &mut engine,
        &conflicting_child,
    ));
    assert!(!engine.recovered_headers.contains_key(&5));
}

#[test]
fn asymptote_reset_promotes_committed_header_for_committed_height() {
    let mut engine = GuardianMajorityEngine::new(AftSafetyMode::Asymptote);
    let previous_collapse = test_canonical_collapse_object(4, None, [44u8; 32], [45u8; 32]);
    engine
        .committed_collapses
        .insert(previous_collapse.height, previous_collapse.clone());
    let mut committed_header = build_progress_parent_header(5, 0);
    link_header_to_previous_collapse(&mut committed_header, &previous_collapse);
    let committed_collapse = derive_canonical_collapse_object_with_previous(
        &committed_header,
        &[],
        Some(&previous_collapse),
    )
    .unwrap();
    let committed_hash = to_root_hash(&committed_header.hash().unwrap()).unwrap();
    engine
        .committed_headers
        .insert(committed_header.height, committed_header);
    engine
        .committed_collapses
        .insert(committed_collapse.height, committed_collapse);

    <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::reset(&mut engine, 5);

    assert_eq!(engine.highest_qc.height, 5);
    assert_eq!(engine.highest_qc.block_hash, committed_hash);
    assert_eq!(
            <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::take_pending_quorum_certificates(
                &mut engine,
            )
            .len(),
            1
        );
}

#[test]
fn asymptote_observe_committed_block_ignores_mismatched_collapse_object() {
    let mut engine = GuardianMajorityEngine::new(AftSafetyMode::Asymptote);
    let previous_collapse = test_canonical_collapse_object(4, None, [46u8; 32], [47u8; 32]);
    engine
        .committed_collapses
        .insert(previous_collapse.height, previous_collapse.clone());
    let mut committed_header = build_progress_parent_header(5, 0);
    link_header_to_previous_collapse(&mut committed_header, &previous_collapse);
    let mut collapse = derive_canonical_collapse_object_with_previous(
        &committed_header,
        &[],
        Some(&previous_collapse),
    )
    .unwrap();
    collapse.resulting_state_root_hash[0] ^= 0xFF;

    let accepted =
        <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::observe_committed_block(
            &mut engine,
            &committed_header,
            Some(&collapse),
        );

    assert!(!accepted);
    assert!(!engine
        .committed_headers
        .contains_key(&committed_header.height));

    <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::reset(&mut engine, 5);

    assert!(engine.highest_qc.height < 5);
}

#[test]
fn asymptote_observe_committed_block_with_matching_collapse_enables_reset_promotion() {
    let mut engine = GuardianMajorityEngine::new(AftSafetyMode::Asymptote);
    let previous_collapse = test_canonical_collapse_object(4, None, [48u8; 32], [49u8; 32]);
    engine
        .committed_collapses
        .insert(previous_collapse.height, previous_collapse.clone());
    let mut committed_header = build_progress_parent_header(5, 0);
    link_header_to_previous_collapse(&mut committed_header, &previous_collapse);
    let committed_hash = to_root_hash(&committed_header.hash().unwrap()).unwrap();
    let collapse = derive_canonical_collapse_object_with_previous(
        &committed_header,
        &[],
        Some(&previous_collapse),
    )
    .unwrap();

    let accepted =
        <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::observe_committed_block(
            &mut engine,
            &committed_header,
            Some(&collapse),
        );

    assert!(accepted);
    <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::reset(&mut engine, 5);

    assert_eq!(engine.highest_qc.height, 5);
    assert_eq!(engine.highest_qc.block_hash, committed_hash);
}

#[test]
fn asymptote_observe_committed_block_with_matching_succinct_collapse_enables_reset_promotion() {
    let _guard = continuity_env_lock().lock().expect("continuity env lock");
    let previous_env = std::env::var("IOI_AFT_CONTINUITY_PROOF_SYSTEM").ok();
    std::env::set_var("IOI_AFT_CONTINUITY_PROOF_SYSTEM", "succinct-sp1-v1");

    let mut engine = GuardianMajorityEngine::new(AftSafetyMode::Asymptote);
    let previous_collapse = test_canonical_collapse_object(4, None, [0x31u8; 32], [0x32u8; 32]);
    engine
        .committed_collapses
        .insert(previous_collapse.height, previous_collapse.clone());
    let mut committed_header = build_progress_parent_header(5, 0);
    link_header_to_previous_collapse(&mut committed_header, &previous_collapse);
    let committed_hash = to_root_hash(&committed_header.hash().unwrap()).unwrap();
    let committed_collapse = derive_canonical_collapse_object_with_previous(
        &committed_header,
        &[],
        Some(&previous_collapse),
    )
    .unwrap();

    let accepted =
        <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::observe_committed_block(
            &mut engine,
            &committed_header,
            Some(&committed_collapse),
        );

    assert!(accepted);
    <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::reset(&mut engine, 5);

    assert_eq!(engine.highest_qc.height, 5);
    assert_eq!(engine.highest_qc.block_hash, committed_hash);

    if let Some(value) = previous_env {
        std::env::set_var("IOI_AFT_CONTINUITY_PROOF_SYSTEM", value);
    } else {
        std::env::remove_var("IOI_AFT_CONTINUITY_PROOF_SYSTEM");
    }
}

#[test]
fn asymptote_observe_committed_block_rejects_corrupted_local_succinct_predecessor_chain() {
    let _guard = continuity_env_lock().lock().expect("continuity env lock");
    let previous_env = std::env::var("IOI_AFT_CONTINUITY_PROOF_SYSTEM").ok();
    std::env::set_var("IOI_AFT_CONTINUITY_PROOF_SYSTEM", "succinct-sp1-v1");

    let mut engine = GuardianMajorityEngine::new(AftSafetyMode::Asymptote);
    let previous_collapse = test_canonical_collapse_object(4, None, [0x41u8; 32], [0x42u8; 32]);
    let mut stored_previous = previous_collapse.clone();
    stored_previous.continuity_recursive_proof.proof_bytes[0] ^= 0xFF;
    engine
        .committed_collapses
        .insert(stored_previous.height, stored_previous);
    let mut committed_header = build_progress_parent_header(5, 0);
    link_header_to_previous_collapse(&mut committed_header, &previous_collapse);
    let committed_collapse = derive_canonical_collapse_object_with_previous(
        &committed_header,
        &[],
        Some(&previous_collapse),
    )
    .unwrap();

    let accepted =
        <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::observe_committed_block(
            &mut engine,
            &committed_header,
            Some(&committed_collapse),
        );

    assert!(!accepted);

    if let Some(value) = previous_env {
        std::env::set_var("IOI_AFT_CONTINUITY_PROOF_SYSTEM", value);
    } else {
        std::env::remove_var("IOI_AFT_CONTINUITY_PROOF_SYSTEM");
    }
}

#[tokio::test]
async fn asymptote_handle_quorum_certificate_does_not_advance_without_local_header() {
    let mut engine = GuardianMajorityEngine::new(AftSafetyMode::Asymptote);
    engine.remember_validator_count(1, 3);
    let qc = QuorumCertificate {
        height: 1,
        view: 0,
        block_hash: [44u8; 32],
        signatures: vec![
            (AccountId([1u8; 32]), vec![1u8]),
            (AccountId([2u8; 32]), vec![2u8]),
        ],
        aggregated_signature: vec![],
        signers_bitfield: vec![],
    };

    <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::handle_quorum_certificate(
        &mut engine,
        qc,
    )
    .await
    .unwrap();

    assert_eq!(engine.highest_qc.height, 0);
    assert!(
            <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::take_pending_quorum_certificates(
                &mut engine,
            )
            .is_empty()
        );
    assert!(engine.safety.next_ready_commit().is_none());
}

#[tokio::test]
async fn asymptote_handle_quorum_certificate_advances_with_local_header() {
    let mut engine = GuardianMajorityEngine::new(AftSafetyMode::Asymptote);
    engine.remember_validator_count(1, 3);
    let header = build_progress_parent_header(1, 0);
    let block_hash = to_root_hash(&header.hash().unwrap()).unwrap();
    engine
        .seen_headers
        .entry((header.height, header.view))
        .or_default()
        .insert(block_hash, header);
    let qc = QuorumCertificate {
        height: 1,
        view: 0,
        block_hash,
        signatures: vec![
            (AccountId([1u8; 32]), vec![1u8]),
            (AccountId([2u8; 32]), vec![2u8]),
        ],
        aggregated_signature: vec![],
        signers_bitfield: vec![],
    };

    <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::handle_quorum_certificate(
        &mut engine,
        qc.clone(),
    )
    .await
    .unwrap();

    assert_eq!(engine.highest_qc.height, qc.height);
    assert_eq!(engine.highest_qc.block_hash, qc.block_hash);
    assert!(engine.safety.next_ready_commit().is_none());
}

#[tokio::test]
async fn asymptote_handle_quorum_certificate_does_not_advance_without_previous_anchor() {
    let mut engine = GuardianMajorityEngine::new(AftSafetyMode::Asymptote);
    engine.remember_validator_count(2, 3);

    let previous_collapse = test_canonical_collapse_object(1, None, [60u8; 32], [61u8; 32]);
    let mut header = build_progress_parent_header(2, 0);
    link_header_to_previous_collapse(&mut header, &previous_collapse);
    let block_hash = to_root_hash(&header.hash().unwrap()).unwrap();
    engine
        .seen_headers
        .entry((header.height, header.view))
        .or_default()
        .insert(block_hash, header);

    let qc = QuorumCertificate {
        height: 2,
        view: 0,
        block_hash,
        signatures: vec![
            (AccountId([1u8; 32]), vec![1u8]),
            (AccountId([2u8; 32]), vec![2u8]),
        ],
        aggregated_signature: vec![],
        signers_bitfield: vec![],
    };

    <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::handle_quorum_certificate(
        &mut engine,
        qc,
    )
    .await
    .unwrap();

    assert_eq!(engine.highest_qc.height, 0);
}

#[tokio::test]
async fn asymptote_handle_quorum_certificate_does_not_advance_without_carried_previous_collapse_certificate(
) {
    let mut engine = GuardianMajorityEngine::new(AftSafetyMode::Asymptote);
    engine.remember_validator_count(2, 3);

    let previous_collapse = test_canonical_collapse_object(1, None, [70u8; 32], [71u8; 32]);
    engine
        .committed_collapses
        .insert(previous_collapse.height, previous_collapse.clone());

    let mut header = build_progress_parent_header(2, 0);
    link_header_to_previous_collapse(&mut header, &previous_collapse);
    header.canonical_collapse_extension_certificate = None;
    let block_hash = to_root_hash(&header.hash().unwrap()).unwrap();
    engine
        .seen_headers
        .entry((header.height, header.view))
        .or_default()
        .insert(block_hash, header);

    let qc = QuorumCertificate {
        height: 2,
        view: 0,
        block_hash,
        signatures: vec![
            (AccountId([1u8; 32]), vec![1u8]),
            (AccountId([2u8; 32]), vec![2u8]),
        ],
        aggregated_signature: vec![],
        signers_bitfield: vec![],
    };

    <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::handle_quorum_certificate(
        &mut engine,
        qc,
    )
    .await
    .unwrap();

    assert!(engine.highest_qc.height < 2);
}

#[tokio::test]
async fn asymptote_handle_quorum_certificate_does_not_advance_with_mismatched_local_previous_collapse(
) {
    let mut engine = GuardianMajorityEngine::new(AftSafetyMode::Asymptote);
    engine.remember_validator_count(3, 3);

    let grandparent_collapse = test_canonical_collapse_object(1, None, [72u8; 32], [73u8; 32]);
    let previous_collapse =
        test_canonical_collapse_object(2, Some(&grandparent_collapse), [74u8; 32], [75u8; 32]);
    engine
        .committed_collapses
        .insert(grandparent_collapse.height, grandparent_collapse.clone());
    engine
        .committed_collapses
        .insert(previous_collapse.height, previous_collapse.clone());

    let mut header = build_progress_parent_header(3, 0);
    link_header_to_previous_collapse(&mut header, &previous_collapse);
    let mut wrong_certificate =
        extension_certificate_from_predecessor(&previous_collapse, header.height);
    wrong_certificate.predecessor_recursive_proof_hash[0] ^= 0xFF;
    header.previous_canonical_collapse_commitment_hash =
        canonical_collapse_commitment_hash_from_object(&previous_collapse).unwrap();
    header.canonical_collapse_extension_certificate = Some(wrong_certificate);
    let block_hash = to_root_hash(&header.hash().unwrap()).unwrap();
    engine
        .seen_headers
        .entry((header.height, header.view))
        .or_default()
        .insert(block_hash, header);

    let qc = QuorumCertificate {
        height: 3,
        view: 0,
        block_hash,
        signatures: vec![
            (AccountId([1u8; 32]), vec![1u8]),
            (AccountId([2u8; 32]), vec![2u8]),
        ],
        aggregated_signature: vec![],
        signers_bitfield: vec![],
    };

    <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::handle_quorum_certificate(
        &mut engine,
        qc,
    )
    .await
    .unwrap();

    assert!(engine.highest_qc.height < 3);
}

#[tokio::test]
async fn asymptote_handle_quorum_certificate_advances_with_recursive_proof_backed_predecessor() {
    let mut engine = GuardianMajorityEngine::new(AftSafetyMode::Asymptote);
    engine.remember_validator_count(3, 3);

    let grandparent_collapse = test_canonical_collapse_object(1, None, [76u8; 32], [77u8; 32]);
    let previous_collapse =
        test_canonical_collapse_object(2, Some(&grandparent_collapse), [78u8; 32], [79u8; 32]);
    engine
        .committed_collapses
        .insert(grandparent_collapse.height, grandparent_collapse.clone());
    engine
        .committed_collapses
        .insert(previous_collapse.height, previous_collapse.clone());

    let mut header = build_progress_parent_header(3, 0);
    link_header_to_collapse_chain(
        &mut header,
        &[previous_collapse.clone(), grandparent_collapse.clone()],
    );
    let block_hash = to_root_hash(&header.hash().unwrap()).unwrap();
    engine
        .seen_headers
        .entry((header.height, header.view))
        .or_default()
        .insert(block_hash, header);

    let qc = QuorumCertificate {
        height: 3,
        view: 0,
        block_hash,
        signatures: vec![
            (AccountId([1u8; 32]), vec![1u8]),
            (AccountId([2u8; 32]), vec![2u8]),
        ],
        aggregated_signature: vec![],
        signers_bitfield: vec![],
    };

    <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::handle_quorum_certificate(
        &mut engine,
        qc.clone(),
    )
    .await
    .unwrap();

    assert_eq!(engine.highest_qc.height, qc.height);
    assert_eq!(engine.highest_qc.block_hash, qc.block_hash);
}

#[tokio::test]
async fn asymptote_handle_quorum_certificate_advances_with_valid_succinct_predecessor_proof() {
    let mut engine = GuardianMajorityEngine::new(AftSafetyMode::Asymptote);
    engine.remember_validator_count(3, 3);

    let grandparent_collapse = test_canonical_collapse_object(1, None, [80u8; 32], [81u8; 32]);
    let mut previous_collapse =
        test_canonical_collapse_object(2, Some(&grandparent_collapse), [82u8; 32], [83u8; 32]);
    bind_succinct_mock_continuity(&mut previous_collapse);
    engine
        .committed_collapses
        .insert(grandparent_collapse.height, grandparent_collapse.clone());
    engine
        .committed_collapses
        .insert(previous_collapse.height, previous_collapse.clone());

    let mut header = build_progress_parent_header(3, 0);
    link_header_to_previous_collapse(&mut header, &previous_collapse);
    let block_hash = to_root_hash(&header.hash().unwrap()).unwrap();
    engine
        .seen_headers
        .entry((header.height, header.view))
        .or_default()
        .insert(block_hash, header);

    let qc = QuorumCertificate {
        height: 3,
        view: 0,
        block_hash,
        signatures: vec![
            (AccountId([1u8; 32]), vec![1u8]),
            (AccountId([2u8; 32]), vec![2u8]),
        ],
        aggregated_signature: vec![],
        signers_bitfield: vec![],
    };

    <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::handle_quorum_certificate(
        &mut engine,
        qc.clone(),
    )
    .await
    .unwrap();

    assert_eq!(engine.highest_qc.height, qc.height);
    assert_eq!(engine.highest_qc.block_hash, qc.block_hash);
}

#[tokio::test]
async fn asymptote_handle_quorum_certificate_rejects_invalid_succinct_predecessor_proof() {
    let mut engine = GuardianMajorityEngine::new(AftSafetyMode::Asymptote);
    engine.remember_validator_count(3, 3);

    let grandparent_collapse = test_canonical_collapse_object(1, None, [84u8; 32], [85u8; 32]);
    let mut previous_collapse =
        test_canonical_collapse_object(2, Some(&grandparent_collapse), [86u8; 32], [87u8; 32]);
    bind_succinct_mock_continuity(&mut previous_collapse);
    previous_collapse
        .continuity_recursive_proof
        .proof_bytes
        .reverse();
    engine
        .committed_collapses
        .insert(grandparent_collapse.height, grandparent_collapse.clone());
    engine
        .committed_collapses
        .insert(previous_collapse.height, previous_collapse.clone());

    let mut header = build_progress_parent_header(3, 0);
    header.previous_canonical_collapse_commitment_hash =
        canonical_collapse_commitment_hash_from_object(&previous_collapse).unwrap();
    header.canonical_collapse_extension_certificate = Some(CanonicalCollapseExtensionCertificate {
        predecessor_commitment: canonical_collapse_commitment(&previous_collapse),
        predecessor_recursive_proof_hash: canonical_collapse_recursive_proof_hash(
            &previous_collapse.continuity_recursive_proof,
        )
        .unwrap(),
    });
    header.parent_state_root = StateRoot(previous_collapse.resulting_state_root_hash.to_vec());
    let block_hash = to_root_hash(&header.hash().unwrap()).unwrap();
    engine
        .seen_headers
        .entry((header.height, header.view))
        .or_default()
        .insert(block_hash, header);

    let qc = QuorumCertificate {
        height: 3,
        view: 0,
        block_hash,
        signatures: vec![
            (AccountId([1u8; 32]), vec![1u8]),
            (AccountId([2u8; 32]), vec![2u8]),
        ],
        aggregated_signature: vec![],
        signers_bitfield: vec![],
    };

    <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::handle_quorum_certificate(
        &mut engine,
        qc,
    )
    .await
    .unwrap();

    assert!(engine.highest_qc.height < 3);
}
