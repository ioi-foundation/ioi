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
    build_publication_frontier, build_reference_canonical_order_certificate,
    build_reference_canonical_order_proof_bytes, canonical_asymptote_observer_assignments_hash,
    canonical_asymptote_observer_challenges_hash, canonical_asymptote_observer_transcripts_hash,
    canonical_collapse_commitment, canonical_collapse_commitment_hash_from_object,
    canonical_collapse_continuity_public_inputs, canonical_collapse_recursive_proof_hash,
    canonical_collapse_succinct_mock_proof_bytes, canonical_order_public_inputs,
    canonical_order_public_inputs_hash, canonical_sealed_finality_proof_signing_bytes,
    derive_asymptote_observer_assignments, derive_canonical_collapse_object,
    derive_canonical_collapse_object_with_previous, derive_guardian_witness_assignments,
    derive_reference_ordering_randomness_beacon, guardian_registry_asymptote_policy_key,
    guardian_registry_checkpoint_key, guardian_registry_committee_account_key,
    guardian_registry_committee_key, guardian_registry_log_key,
    guardian_registry_observer_canonical_abort_key, guardian_registry_observer_canonical_close_key,
    guardian_registry_observer_challenge_commitment_key,
    guardian_registry_observer_transcript_commitment_key, guardian_registry_witness_key,
    guardian_registry_witness_seed_key, guardian_registry_witness_set_key,
    recovered_restart_block_header_entry, set_canonical_collapse_archived_recovered_history_anchor,
    write_validator_sets, AftRecoveredStateSurface, AsymptoteObserverCanonicalAbort,
    AsymptoteObserverCanonicalClose, AsymptoteObserverCertificate, AsymptoteObserverChallenge,
    AsymptoteObserverChallengeCommitment, AsymptoteObserverCloseCertificate,
    AsymptoteObserverCorrelationBudget, AsymptoteObserverTranscript,
    AsymptoteObserverTranscriptCommitment, AsymptoteObserverVerdict, AsymptotePolicy,
    AsymptoteVetoKind, AsymptoteVetoProof, BulletinAvailabilityCertificate, BulletinCommitment,
    CanonicalCollapseContinuityProofSystem, CanonicalOrderAbort, CanonicalOrderAbortReason,
    CanonicalOrderCertificate, CanonicalOrderProof, CanonicalOrderProofSystem, CollapseState,
    FinalityTier, GuardianCommitteeMember, GuardianLogCheckpoint, GuardianLogProof,
    GuardianTransparencyLogDescriptor, GuardianWitnessCommitteeManifest,
    GuardianWitnessRecoveryBinding, OmissionProof, RecoverableSlotPayloadV5, SealedFinalityProof,
    SignatureProof, SignatureSuite, StateRoot, ValidatorSetV1, ValidatorSetsV1, ValidatorV1,
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

