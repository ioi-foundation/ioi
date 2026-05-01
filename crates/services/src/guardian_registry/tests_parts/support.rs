use super::*;
use ioi_api::services::access::ServiceDirectory;
use ioi_api::state::StateScanIter;
use ioi_api::transaction::context::TxContext;
use ioi_types::app::{
    aft_archived_recovered_history_checkpoint_hash_key,
    aft_archived_recovered_history_profile_activation_height_key,
    aft_archived_recovered_history_profile_activation_key,
    aft_archived_recovered_history_profile_hash_key,
    aft_archived_recovered_history_retention_receipt_key,
    aft_archived_recovered_history_segment_hash_key, aft_archived_recovered_history_segment_key,
    aft_archived_recovered_restart_page_key, aft_bulletin_availability_certificate_key,
    aft_bulletin_commitment_key, aft_bulletin_custody_receipt_key, aft_bulletin_entry_key,
    aft_bulletin_reconstruction_certificate_key, aft_bulletin_retrievability_profile_key,
    aft_bulletin_shard_manifest_key, aft_canonical_bulletin_close_key,
    aft_canonical_collapse_object_key, aft_canonical_order_abort_key,
    aft_missing_recovery_share_key, aft_omission_proof_key, aft_order_certificate_key,
    aft_publication_frontier_contradiction_key, aft_publication_frontier_key,
    aft_recovered_publication_bundle_key, aft_recovery_capsule_key,
    aft_recovery_share_material_key, aft_recovery_share_receipt_key,
    aft_recovery_witness_certificate_key, archived_recovered_history_retained_through_height,
    build_archived_recovered_history_checkpoint, build_archived_recovered_history_profile,
    build_archived_recovered_history_profile_activation,
    build_archived_recovered_history_retention_receipt, build_archived_recovered_history_segment,
    build_archived_recovered_restart_page, build_bulletin_custody_receipt,
    build_bulletin_retrievability_profile, build_bulletin_shard_manifest,
    build_bulletin_surface_entries,
    build_committed_surface_canonical_order_certificate,
    canonical_archived_recovered_history_checkpoint_hash,
    canonical_archived_recovered_history_profile_hash,
    canonical_archived_recovered_history_retention_receipt_hash,
    canonical_archived_recovered_history_segment_hash,
    canonical_asymptote_observer_canonical_close_hash, canonical_bulletin_close_hash,
    canonical_bulletin_custody_assignment_hash, canonical_bulletin_custody_receipt_hash,
    canonical_bulletin_custody_response_hash, canonical_bulletin_reconstruction_abort_hash,
    canonical_bulletin_reconstruction_certificate_hash,
    canonical_bulletin_retrievability_profile_hash, canonical_bulletin_shard_manifest_hash,
    canonical_order_certificate_hash, canonical_order_publication_bundle_hash,
    canonical_recoverable_slot_payload_v4_hash, canonical_recoverable_slot_payload_v5_hash,
    canonical_recovery_capsule_hash, canonical_transaction_root_from_hashes,
    canonical_validator_sets_hash, canonicalize_transactions_for_header,
    derive_canonical_order_execution_object, encode_coded_recovery_shards,
    guardian_registry_effect_nullifier_key, guardian_registry_effect_verifier_key,
    guardian_registry_log_key, guardian_registry_observer_canonical_abort_key,
    guardian_registry_observer_canonical_close_key,
    guardian_registry_observer_challenge_commitment_key, guardian_registry_observer_challenge_key,
    guardian_registry_observer_transcript_commitment_key,
    guardian_registry_observer_transcript_key, guardian_registry_sealed_effect_key,
    read_validator_sets, recover_canonical_order_publication_bundle_from_share_materials,
    recover_full_canonical_order_surface_from_share_materials, recovered_certified_header_prefix,
    recovered_restart_block_header_entry, write_validator_sets, AccountId,
    ArchivedRecoveredHistoryCheckpoint, ArchivedRecoveredHistoryCheckpointUpdateRule,
    ArchivedRecoveredHistoryProfile, ArchivedRecoveredHistoryProfileActivation,
    ArchivedRecoveredHistoryRetentionReceipt, ArchivedRecoveredHistorySegment,
    ArchivedRecoveredRestartPage, AsymptoteObserverAssignment, AsymptoteObserverCanonicalAbort,
    AsymptoteObserverCanonicalClose, AsymptoteObserverChallenge,
    AsymptoteObserverChallengeCommitment, AsymptoteObserverChallengeKind,
    AsymptoteObserverObservationRequest, AsymptoteObserverSealingMode, AsymptoteObserverStatement,
    AsymptoteObserverTranscript, AsymptoteObserverTranscriptCommitment, AsymptoteObserverVerdict,
    BlockHeader, BulletinAvailabilityCertificate, BulletinCommitment, BulletinCustodyReceipt,
    BulletinReconstructionAbort, BulletinReconstructionCertificate,
    BulletinRetrievabilityChallenge, BulletinRetrievabilityChallengeKind,
    BulletinRetrievabilityProfile, BulletinShardManifest, BulletinSurfaceEntry,
    CanonicalBulletinClose, CanonicalCollapseObject, CanonicalOrderAbort,
    CanonicalOrderAbortReason, CanonicalOrderCertificate, CanonicalOrderProof,
    CanonicalOrderProofSystem, CanonicalOrderPublicationBundle, ChainId, ChainTransaction,
    EffectProofSystem, EffectProofVerifierDescriptor, GuardianCommitteeMember,
    GuardianQuorumCertificate, GuardianTransparencyLogDescriptor, GuardianWitnessEpochSeed,
    MissingRecoveryShare, OmissionProof, PublicationFrontier, PublicationFrontierContradiction,
    PublicationFrontierContradictionKind, QuorumCertificate, RecoverableSlotPayloadV3,
    RecoverableSlotPayloadV5, RecoveredPublicationBundle, RecoveredSegmentFoldCursor, RecoveryCapsule,
    RecoveryCodingDescriptor, RecoveryCodingFamily, RecoveryShareMaterial, RecoveryShareReceipt,
    RecoveryWitnessCertificate, SealedEffectClass, SealedEffectRecord, SignHeader, SignatureProof,
    SignatureSuite, StateRoot, SystemPayload, SystemTransaction, ValidatorSetV1, ValidatorSetsV1,
    ValidatorV1, AFT_ACTIVE_ARCHIVED_RECOVERED_HISTORY_PROFILE_KEY,
    AFT_LATEST_ARCHIVED_RECOVERED_HISTORY_CHECKPOINT_KEY,
    AFT_LATEST_ARCHIVED_RECOVERED_HISTORY_PROFILE_ACTIVATION_KEY,
};
use ioi_types::keys::{EVIDENCE_REGISTRY_KEY, QUARANTINED_VALIDATORS_KEY, VALIDATOR_SET_KEY};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

struct MockState {
    data: BTreeMap<Vec<u8>, Vec<u8>>,
}

impl Default for MockState {
    fn default() -> Self {
        let mut data = BTreeMap::new();
        data.insert(
            VALIDATOR_SET_KEY.to_vec(),
            write_validator_sets(&validator_sets(&[(18, 1), (145, 1), (19, 1)]))
                .expect("encode default guardian test validator set"),
        );
        Self { data }
    }
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

fn canonical_order_publication_bundle_with_retrievability(
    certificate: &CanonicalOrderCertificate,
    bulletin_entries: Vec<BulletinSurfaceEntry>,
) -> CanonicalOrderPublicationBundle {
    let bulletin_retrievability_profile = build_bulletin_retrievability_profile(
        &certificate.bulletin_commitment,
        &certificate.bulletin_availability_certificate,
    )
    .expect("build bulletin retrievability profile");
    let bulletin_shard_manifest = build_bulletin_shard_manifest(
        &certificate.bulletin_commitment,
        &certificate.bulletin_availability_certificate,
        &bulletin_retrievability_profile,
        &bulletin_entries,
    )
    .expect("build bulletin shard manifest");
    let bulletin_custody_receipt =
        build_bulletin_custody_receipt(&bulletin_retrievability_profile, &bulletin_shard_manifest)
            .expect("build bulletin custody receipt");
    CanonicalOrderPublicationBundle {
        bulletin_commitment: certificate.bulletin_commitment.clone(),
        bulletin_entries,
        bulletin_availability_certificate: certificate.bulletin_availability_certificate.clone(),
        bulletin_retrievability_profile,
        bulletin_shard_manifest,
        bulletin_custody_receipt,
        canonical_order_certificate: certificate.clone(),
    }
}

fn sample_canonical_order_publication_bundle_with_retrievability(
    height: u64,
    view: u64,
    seed: u8,
) -> CanonicalOrderPublicationBundle {
    let base_header = ioi_types::app::BlockHeader {
        height,
        view,
        parent_hash: [seed; 32],
        parent_state_root: StateRoot(vec![seed.wrapping_add(1); 32]),
        state_root: StateRoot(vec![seed.wrapping_add(2); 32]),
        transactions_root: Vec::new(),
        timestamp: 1_760_001_000 + u64::from(seed),
        timestamp_ms: (1_760_001_000 + u64::from(seed)) * 1000,
        gas_used: 0,
        validator_set: Vec::new(),
        producer_account_id: AccountId([seed.wrapping_add(3); 32]),
        producer_key_suite: SignatureSuite::ED25519,
        producer_pubkey_hash: [seed.wrapping_add(4); 32],
        producer_pubkey: Vec::new(),
        signature: Vec::new(),
        oracle_counter: 0,
        oracle_trace_hash: [0u8; 32],
        parent_qc: QuorumCertificate::default(),
        previous_canonical_collapse_commitment_hash: [0u8; 32],
        canonical_collapse_extension_certificate: None,
        publication_frontier: None,
        guardian_certificate: None,
        sealed_finality_proof: None,
        canonical_order_certificate: None,
        timeout_certificate: None,
    };
    let tx_one = ChainTransaction::System(Box::new(SystemTransaction {
        header: SignHeader {
            account_id: AccountId([seed.wrapping_add(5); 32]),
            nonce: 1,
            chain_id: ChainId(1),
            tx_version: 1,
            session_auth: None,
        },
        payload: SystemPayload::CallService {
            service_id: "guardian_registry".into(),
            method: "publish_aft_bulletin_commitment@v1".into(),
            params: vec![seed],
        },
        signature_proof: SignatureProof::default(),
    }));
    let tx_two = ChainTransaction::System(Box::new(SystemTransaction {
        header: SignHeader {
            account_id: AccountId([seed.wrapping_add(6); 32]),
            nonce: 1,
            chain_id: ChainId(1),
            tx_version: 1,
            session_auth: None,
        },
        payload: SystemPayload::CallService {
            service_id: "guardian_registry".into(),
            method: "publish_aft_canonical_order_artifact_bundle@v1".into(),
            params: vec![seed.wrapping_add(1)],
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
    canonical_order_publication_bundle_with_retrievability(
        &certificate,
        build_bulletin_surface_entries(header.height, &ordered_transactions).unwrap(),
    )
}

fn seed_endogenous_bulletin_surface_state(
    state: &mut MockState,
    bundle: &CanonicalOrderPublicationBundle,
    bulletin_entries: &[BulletinSurfaceEntry],
    include_profile: bool,
    include_manifest: bool,
    include_receipt: bool,
) {
    state
        .insert(
            &aft_bulletin_commitment_key(bundle.bulletin_commitment.height),
            &codec::to_bytes_canonical(&bundle.bulletin_commitment).unwrap(),
        )
        .unwrap();
    for entry in bulletin_entries {
        state
            .insert(
                &aft_bulletin_entry_key(entry.height, &entry.tx_hash),
                &codec::to_bytes_canonical(entry).unwrap(),
            )
            .unwrap();
    }
    state
        .insert(
            &aft_bulletin_availability_certificate_key(
                bundle.bulletin_availability_certificate.height,
            ),
            &codec::to_bytes_canonical(&bundle.bulletin_availability_certificate).unwrap(),
        )
        .unwrap();
    let validator_sets = validator_sets(&[(18, 1), (145, 1), (19, 1)]);
    state
        .insert(
            VALIDATOR_SET_KEY,
            &write_validator_sets(&validator_sets).unwrap(),
        )
        .unwrap();
    if include_profile {
        state
            .insert(
                &aft_bulletin_retrievability_profile_key(
                    bundle.bulletin_retrievability_profile.height,
                ),
                &codec::to_bytes_canonical(&bundle.bulletin_retrievability_profile).unwrap(),
            )
            .unwrap();
    }
    if include_manifest {
        state
            .insert(
                &aft_bulletin_shard_manifest_key(bundle.bulletin_shard_manifest.height),
                &codec::to_bytes_canonical(&bundle.bulletin_shard_manifest).unwrap(),
            )
            .unwrap();
        let assignment = build_bulletin_custody_assignment(
            &bundle.bulletin_retrievability_profile,
            &bundle.bulletin_shard_manifest,
            &validator_sets.current,
        )
        .unwrap();
        state
            .insert(
                &aft_bulletin_custody_assignment_key(assignment.height),
                &codec::to_bytes_canonical(&assignment).unwrap(),
            )
            .unwrap();
        if include_receipt {
            let response = build_bulletin_custody_response(
                &bundle.bulletin_commitment,
                &bundle.bulletin_retrievability_profile,
                &bundle.bulletin_shard_manifest,
                &assignment,
                &bundle.bulletin_custody_receipt,
                bulletin_entries,
            )
            .unwrap();
            state
                .insert(
                    &aft_bulletin_custody_response_key(response.height),
                    &codec::to_bytes_canonical(&response).unwrap(),
                )
                .unwrap();
        }
    }
    if include_receipt {
        state
            .insert(
                &aft_bulletin_custody_receipt_key(bundle.bulletin_custody_receipt.height),
                &codec::to_bytes_canonical(&bundle.bulletin_custody_receipt).unwrap(),
            )
            .unwrap();
    }
}

fn sample_bulletin_custody_plane_hashes(
    bundle: &CanonicalOrderPublicationBundle,
    bulletin_entries: &[BulletinSurfaceEntry],
) -> ([u8; 32], [u8; 32]) {
    let validator_sets = validator_sets(&[(18, 1), (145, 1), (19, 1)]);
    let assignment = build_bulletin_custody_assignment(
        &bundle.bulletin_retrievability_profile,
        &bundle.bulletin_shard_manifest,
        &validator_sets.current,
    )
    .unwrap();
    let response = build_bulletin_custody_response(
        &bundle.bulletin_commitment,
        &bundle.bulletin_retrievability_profile,
        &bundle.bulletin_shard_manifest,
        &assignment,
        &bundle.bulletin_custody_receipt,
        bulletin_entries,
    )
    .unwrap();
    (
        canonical_bulletin_custody_assignment_hash(&assignment).unwrap(),
        canonical_bulletin_custody_response_hash(&response).unwrap(),
    )
}

fn verified_canonical_bulletin_close_for_bundle(
    bundle: &CanonicalOrderPublicationBundle,
) -> CanonicalBulletinClose {
    verify_canonical_order_publication_bundle(bundle).expect("verify canonical publication bundle")
}

fn canonical_bulletin_close_from_recovered_surface(
    full_surface: &RecoverableSlotPayloadV5,
) -> CanonicalBulletinClose {
    codec::from_bytes_canonical(&full_surface.canonical_bulletin_close_bytes)
        .expect("decode recovered canonical bulletin close")
}

fn assert_bulletin_reconstruction_abort_present(
    state: &MockState,
    height: u64,
    expected_kind: BulletinRetrievabilityChallengeKind,
) {
    let reconstruction_abort: BulletinReconstructionAbort = codec::from_bytes_canonical(
        &state
            .get(&aft_bulletin_reconstruction_abort_key(height))
            .unwrap()
            .expect("bulletin reconstruction abort stored"),
    )
    .unwrap();
    assert_eq!(reconstruction_abort.height, height);
    assert_eq!(reconstruction_abort.kind, expected_kind);
    assert_ne!(
        canonical_bulletin_reconstruction_abort_hash(&reconstruction_abort).unwrap(),
        [0u8; 32]
    );
}

fn assert_bulletin_reconstruction_certificate_present(
    state: &MockState,
    height: u64,
    expected_entry_count: u32,
) {
    let reconstruction_certificate: BulletinReconstructionCertificate =
        codec::from_bytes_canonical(
            &state
                .get(&aft_bulletin_reconstruction_certificate_key(height))
                .unwrap()
                .expect("bulletin reconstruction certificate stored"),
        )
        .unwrap();
    assert_eq!(reconstruction_certificate.height, height);
    assert_eq!(
        reconstruction_certificate.reconstructed_entry_count,
        expected_entry_count
    );
    assert_ne!(
        canonical_bulletin_reconstruction_certificate_hash(&reconstruction_certificate).unwrap(),
        [0u8; 32]
    );
}

fn validator(account: u8, weight: u128) -> ValidatorV1 {
    ValidatorV1 {
        account_id: AccountId([account; 32]),
        weight,
        consensus_key: Default::default(),
    }
}

fn sample_recovery_capsule(height: u64) -> RecoveryCapsule {
    RecoveryCapsule {
        height,
        coding: xor_recovery_coding(3, 2),
        recovery_committee_root_hash: [height as u8 + 1; 32],
        payload_commitment_hash: [height as u8 + 2; 32],
        coding_root_hash: [height as u8 + 3; 32],
        recovery_window_close_ms: 1_750_002_000_000 + height,
    }
}

fn xor_recovery_coding(share_count: u16, recovery_threshold: u16) -> RecoveryCodingDescriptor {
    RecoveryCodingDescriptor {
        family: RecoveryCodingFamily::SystematicXorKOfKPlus1V1,
        share_count,
        recovery_threshold,
    }
}

fn gf256_recovery_coding(share_count: u16, recovery_threshold: u16) -> RecoveryCodingDescriptor {
    RecoveryCodingDescriptor {
        family: RecoveryCodingFamily::SystematicGf256KOfNV1,
        share_count,
        recovery_threshold,
    }
}

fn nonzero_test_byte(value: u8) -> u8 {
    if value == 0 {
        1
    } else {
        value
    }
}

fn sample_recovery_witness_certificate(
    capsule: &RecoveryCapsule,
    witness_manifest_hash: [u8; 32],
    share_commitment_hash: [u8; 32],
) -> RecoveryWitnessCertificate {
    RecoveryWitnessCertificate {
        height: capsule.height,
        epoch: 19,
        witness_manifest_hash,
        recovery_capsule_hash: canonical_recovery_capsule_hash(capsule)
            .expect("recovery capsule hash"),
        share_commitment_hash,
    }
}

fn sample_recovered_publication_bundle_fixture_with_scheme(
    height: u64,
    seed: u8,
    coding: RecoveryCodingDescriptor,
    support_share_indices: &[u16],
) -> (
    RecoveryCapsule,
    Vec<RecoveryWitnessCertificate>,
    Vec<RecoveryShareMaterial>,
    RecoveredPublicationBundle,
) {
    sample_recovered_publication_bundle_fixture_with_scheme_and_optional_omission(
        height,
        seed,
        coding,
        support_share_indices,
        None,
        None,
    )
}

fn sample_recovered_publication_bundle_fixture_with_scheme_and_optional_omission(
    height: u64,
    seed: u8,
    coding: RecoveryCodingDescriptor,
    support_share_indices: &[u16],
    parent_block_hash: Option<[u8; 32]>,
    omission: Option<(AccountId, [u8; 32])>,
) -> (
    RecoveryCapsule,
    Vec<RecoveryWitnessCertificate>,
    Vec<RecoveryShareMaterial>,
    RecoveredPublicationBundle,
) {
    let share_count = coding.share_count;
    let recovery_threshold = coding.recovery_threshold;
    assert!(coding
        .family_contract()
        .expect("recovery-family contract")
        .supports_coded_payload_reconstruction());
    assert_eq!(support_share_indices.len(), usize::from(recovery_threshold));

    let mut header = BlockHeader {
        height,
        view: 4,
        parent_hash: parent_block_hash.unwrap_or([nonzero_test_byte(seed.wrapping_add(1)); 32]),
        parent_state_root: StateRoot(vec![nonzero_test_byte(seed.wrapping_add(2)); 32]),
        state_root: StateRoot(vec![nonzero_test_byte(seed.wrapping_add(3)); 32]),
        transactions_root: vec![],
        timestamp: 1_750_010_000 + height,
        timestamp_ms: (1_750_010_000 + height) * 1_000,
        gas_used: 0,
        validator_set: Vec::new(),
        producer_account_id: AccountId([nonzero_test_byte(seed.wrapping_add(4)); 32]),
        producer_key_suite: SignatureSuite::ED25519,
        producer_pubkey_hash: [nonzero_test_byte(seed.wrapping_add(5)); 32],
        producer_pubkey: Vec::new(),
        signature: Vec::new(),
        oracle_counter: 0,
        oracle_trace_hash: [0u8; 32],
        parent_qc: QuorumCertificate::default(),
        previous_canonical_collapse_commitment_hash: [0u8; 32],
        canonical_collapse_extension_certificate: None,
        publication_frontier: None,
        guardian_certificate: None,
        sealed_finality_proof: None,
        canonical_order_certificate: None,
        timeout_certificate: None,
    };
    let tx_one = ChainTransaction::System(Box::new(SystemTransaction {
        header: SignHeader {
            account_id: AccountId([nonzero_test_byte(seed.wrapping_add(10)); 32]),
            nonce: 1,
            chain_id: ChainId(1),
            tx_version: 1,
            session_auth: None,
        },
        payload: SystemPayload::CallService {
            service_id: "guardian_registry".into(),
            method: "publish_aft_bulletin_commitment@v1".into(),
            params: vec![seed],
        },
        signature_proof: SignatureProof::default(),
    }));
    let tx_two = ChainTransaction::System(Box::new(SystemTransaction {
        header: SignHeader {
            account_id: AccountId([nonzero_test_byte(seed.wrapping_add(11)); 32]),
            nonce: 1,
            chain_id: ChainId(1),
            tx_version: 1,
            session_auth: None,
        },
        payload: SystemPayload::CallService {
            service_id: "guardian_registry".into(),
            method: "publish_aft_canonical_order_artifact_bundle@v1".into(),
            params: vec![seed.wrapping_add(1)],
        },
        signature_proof: SignatureProof::default(),
    }));
    let ordered_transactions = canonicalize_transactions_for_header(&header, &[tx_one, tx_two])
        .expect("canonicalized transactions");
    let tx_hashes: Vec<[u8; 32]> = ordered_transactions
        .iter()
        .map(|tx| tx.hash().expect("tx hash"))
        .collect();
    header.transactions_root =
        canonical_transaction_root_from_hashes(&tx_hashes).expect("transactions root");
    let mut certificate =
        build_committed_surface_canonical_order_certificate(&header, &ordered_transactions)
            .expect("build committed-surface certificate");
    if let Some((offender_account_id, tx_hash)) = omission {
        certificate.omission_proofs = vec![OmissionProof {
                height,
                offender_account_id,
                tx_hash,
                bulletin_root: certificate.bulletin_commitment.bulletin_root,
                details:
                    "recovered publication bundle omission remains decisive without membership penalties"
                        .into(),
            }];
    }
    header.canonical_order_certificate = Some(certificate.clone());
    let publication_bundle = if certificate.omission_proofs.is_empty() {
        let execution_object =
            derive_canonical_order_execution_object(&header, &ordered_transactions)
                .expect("derive canonical order execution object");
        canonical_order_publication_bundle_with_retrievability(
            &execution_object.canonical_order_certificate,
            execution_object.bulletin_entries.clone(),
        )
    } else {
        canonical_order_publication_bundle_with_retrievability(
            &certificate,
            build_bulletin_surface_entries(height, &ordered_transactions)
                .expect("build bulletin surface entries"),
        )
    };
    let block_hash = header.hash().expect("header hash");
    let block_commitment_hash: [u8; 32] = block_hash
        .as_slice()
        .try_into()
        .expect("32-byte block hash");
    let payload = RecoverableSlotPayloadV3 {
        height,
        view: header.view,
        producer_account_id: header.producer_account_id,
        block_commitment_hash,
        parent_block_hash: header.parent_hash,
        canonical_order_certificate: certificate,
        ordered_transaction_bytes: ordered_transactions
            .iter()
            .map(|transaction| codec::to_bytes_canonical(transaction).expect("encode tx"))
            .collect(),
        canonical_order_publication_bundle_bytes: codec::to_bytes_canonical(&publication_bundle)
            .expect("encode publication bundle"),
    };
    let payload_bytes = codec::to_bytes_canonical(&payload).expect("encode payload");
    let shard_bytes =
        encode_coded_recovery_shards(coding, &payload_bytes).expect("encode coded shards");
    assert_eq!(shard_bytes.len(), usize::from(share_count));
    let (payload_v4, _, bulletin_close) =
        ioi_types::app::lift_recoverable_slot_payload_v3_to_v4(&payload)
            .expect("lift recoverable payload v4");
    let (payload_v5, _, _, _) = ioi_types::app::lift_recoverable_slot_payload_v4_to_v5(&payload_v4)
        .expect("lift recoverable payload v5");

    let capsule = RecoveryCapsule {
        height,
        coding,
        recovery_committee_root_hash: [nonzero_test_byte(seed.wrapping_add(40)); 32],
        payload_commitment_hash: [nonzero_test_byte(seed.wrapping_add(41)); 32],
        coding_root_hash: [nonzero_test_byte(seed.wrapping_add(42)); 32],
        recovery_window_close_ms: 1_750_002_000_000 + height,
    };
    let witnesses = support_share_indices
        .iter()
        .enumerate()
        .map(|(offset, _)| {
            let mut witness_manifest_hash = [0u8; 32];
            witness_manifest_hash[..8].copy_from_slice(&height.to_be_bytes());
            witness_manifest_hash[8] = nonzero_test_byte((offset as u8).wrapping_add(1));
            witness_manifest_hash[9] = nonzero_test_byte(seed.wrapping_add(20 + offset as u8));
            witness_manifest_hash
        })
        .collect::<Vec<_>>();
    let share_commitments = support_share_indices
        .iter()
        .enumerate()
        .map(|(offset, _)| {
            let mut share_commitment_hash = [0u8; 32];
            share_commitment_hash[..8].copy_from_slice(&height.to_be_bytes());
            share_commitment_hash[8] = nonzero_test_byte((offset as u8).wrapping_add(1));
            share_commitment_hash[9] = nonzero_test_byte(seed.wrapping_add(30 + offset as u8));
            share_commitment_hash
        })
        .collect::<Vec<_>>();
    let certificates = witnesses
        .iter()
        .zip(share_commitments.iter())
        .map(|(witness_manifest_hash, share_commitment_hash)| {
            sample_recovery_witness_certificate(
                &capsule,
                *witness_manifest_hash,
                *share_commitment_hash,
            )
        })
        .collect::<Vec<_>>();
    let materials = witnesses
        .iter()
        .zip(support_share_indices.iter())
        .zip(share_commitments.iter())
        .map(
            |((witness_manifest_hash, share_index), share_commitment_hash)| RecoveryShareMaterial {
                height,
                witness_manifest_hash: *witness_manifest_hash,
                block_commitment_hash,
                coding,
                share_index: *share_index,
                share_commitment_hash: *share_commitment_hash,
                material_bytes: shard_bytes[usize::from(*share_index)].clone(),
            },
        )
        .collect::<Vec<_>>();
    let recovered = RecoveredPublicationBundle {
        height,
        block_commitment_hash,
        parent_block_commitment_hash: header.parent_hash,
        coding,
        supporting_witness_manifest_hashes: witnesses,
        recoverable_slot_payload_hash: canonical_recoverable_slot_payload_v4_hash(&payload_v4)
            .expect("payload hash"),
        recoverable_full_surface_hash: canonical_recoverable_slot_payload_v5_hash(&payload_v5)
            .expect("full surface hash"),
        canonical_order_publication_bundle_hash: canonical_order_publication_bundle_hash(
            &publication_bundle,
        )
        .expect("publication bundle hash"),
        canonical_bulletin_close_hash: canonical_bulletin_close_hash(&bulletin_close)
            .expect("bulletin close hash"),
    };
    (capsule, certificates, materials, recovered)
}

fn sample_recovered_publication_bundle_fixture_3_of_5_with_omission(
    height: u64,
    seed: u8,
    offender_account_id: AccountId,
    tx_hash: [u8; 32],
) -> (
    RecoveryCapsule,
    Vec<RecoveryWitnessCertificate>,
    Vec<RecoveryShareMaterial>,
    RecoveredPublicationBundle,
) {
    sample_recovered_publication_bundle_fixture_with_scheme_and_optional_omission(
        height,
        seed,
        gf256_recovery_coding(5, 3),
        &[0, 3, 4],
        None,
        Some((offender_account_id, tx_hash)),
    )
}

fn sample_recovered_publication_bundle_fixture(
    height: u64,
    seed: u8,
) -> (
    RecoveryCapsule,
    Vec<RecoveryWitnessCertificate>,
    Vec<RecoveryShareMaterial>,
    RecoveredPublicationBundle,
) {
    sample_recovered_publication_bundle_fixture_with_scheme(
        height,
        seed,
        gf256_recovery_coding(4, 2),
        &[1, 3],
    )
}

fn sample_recovered_publication_bundle_fixture_3_of_5(
    height: u64,
    seed: u8,
) -> (
    RecoveryCapsule,
    Vec<RecoveryWitnessCertificate>,
    Vec<RecoveryShareMaterial>,
    RecoveredPublicationBundle,
) {
    sample_recovered_publication_bundle_fixture_with_scheme(
        height,
        seed,
        gf256_recovery_coding(5, 3),
        &[0, 3, 4],
    )
}

fn sample_recovered_publication_bundle_fixture_4_of_6(
    height: u64,
    seed: u8,
) -> (
    RecoveryCapsule,
    Vec<RecoveryWitnessCertificate>,
    Vec<RecoveryShareMaterial>,
    RecoveredPublicationBundle,
) {
    sample_recovered_publication_bundle_fixture_with_scheme(
        height,
        seed,
        gf256_recovery_coding(6, 4),
        &[0, 2, 4, 5],
    )
}

fn sample_recovered_publication_bundle_fixture_3_of_7(
    height: u64,
    seed: u8,
) -> (
    RecoveryCapsule,
    Vec<RecoveryWitnessCertificate>,
    Vec<RecoveryShareMaterial>,
    RecoveredPublicationBundle,
) {
    sample_recovered_publication_bundle_fixture_with_scheme(
        height,
        seed,
        gf256_recovery_coding(7, 3),
        &[0, 3, 6],
    )
}

fn sample_recovered_publication_bundle_fixture_3_of_7_with_parent(
    height: u64,
    seed: u8,
    parent_block_hash: [u8; 32],
) -> (
    RecoveryCapsule,
    Vec<RecoveryWitnessCertificate>,
    Vec<RecoveryShareMaterial>,
    RecoveredPublicationBundle,
) {
    sample_recovered_publication_bundle_fixture_with_scheme_and_optional_omission(
        height,
        seed,
        gf256_recovery_coding(7, 3),
        &[0, 3, 6],
        Some(parent_block_hash),
        None,
    )
}

fn sample_recovered_publication_bundle_fixture_3_of_7_with_parent_and_omission(
    height: u64,
    seed: u8,
    parent_block_hash: [u8; 32],
    offender_account_id: AccountId,
    tx_hash: [u8; 32],
) -> (
    RecoveryCapsule,
    Vec<RecoveryWitnessCertificate>,
    Vec<RecoveryShareMaterial>,
    RecoveredPublicationBundle,
) {
    sample_recovered_publication_bundle_fixture_with_scheme_and_optional_omission(
        height,
        seed,
        gf256_recovery_coding(7, 3),
        &[0, 3, 6],
        Some(parent_block_hash),
        Some((offender_account_id, tx_hash)),
    )
}

fn sample_recovered_publication_bundle_fixture_4_of_7(
    height: u64,
    seed: u8,
) -> (
    RecoveryCapsule,
    Vec<RecoveryWitnessCertificate>,
    Vec<RecoveryShareMaterial>,
    RecoveredPublicationBundle,
) {
    sample_recovered_publication_bundle_fixture_with_scheme(
        height,
        seed,
        gf256_recovery_coding(7, 4),
        &[0, 2, 4, 6],
    )
}

fn seed_previous_canonical_collapse_placeholder_if_absent(
    state: &mut MockState,
    height: u64,
    seed: u8,
) {
    if height <= 1 {
        return;
    }
    let key = aft_canonical_collapse_object_key(height - 1);
    if state.get(&key).unwrap().is_some() {
        return;
    }
    let previous = CanonicalCollapseObject {
        height: height - 1,
        previous_canonical_collapse_commitment_hash: [0u8; 32],
        continuity_accumulator_hash: [0u8; 32],
        continuity_recursive_proof: Default::default(),
        ordering: ioi_types::app::CanonicalOrderingCollapse {
            height: height - 1,
            kind: CanonicalCollapseKind::Close,
            bulletin_commitment_hash: [seed; 32],
            bulletin_availability_certificate_hash: [seed.wrapping_add(1); 32],
            bulletin_retrievability_profile_hash: [0u8; 32],
            bulletin_shard_manifest_hash: [0u8; 32],
            bulletin_custody_receipt_hash: [0u8; 32],
            bulletin_close_hash: [seed.wrapping_add(2); 32],
            canonical_order_certificate_hash: [seed.wrapping_add(3); 32],
        },
        sealing: None,
        transactions_root_hash: [seed.wrapping_add(4); 32],
        resulting_state_root_hash: [seed.wrapping_add(5); 32],
        archived_recovered_history_checkpoint_hash: [0u8; 32],
        archived_recovered_history_profile_activation_hash: [0u8; 32],
        archived_recovered_history_retention_receipt_hash: [0u8; 32],
    };
    state
        .insert(&key, &codec::to_bytes_canonical(&previous).unwrap())
        .unwrap();
}

fn assert_conflicting_recovered_publication_bundles_materialize_abort(
    capsule: RecoveryCapsule,
    certificates: Vec<RecoveryWitnessCertificate>,
    materials: Vec<RecoveryShareMaterial>,
    recovered: RecoveredPublicationBundle,
    conflicting_certificates: Vec<RecoveryWitnessCertificate>,
    conflicting_materials: Vec<RecoveryShareMaterial>,
    conflicting_recovered: RecoveredPublicationBundle,
) {
    let registry = production_registry();
    let mut state = MockState::default();
    seed_previous_canonical_collapse_placeholder_if_absent(&mut state, recovered.height, 0xA0);
    with_ctx(|ctx| {
        run_async(registry.handle_service_call(
            &mut state,
            "publish_aft_recovery_capsule@v1",
            &codec::to_bytes_canonical(&capsule).unwrap(),
            ctx,
        ))
        .unwrap();
        for certificate in &certificates {
            run_async(registry.handle_service_call(
                &mut state,
                "publish_aft_recovery_witness_certificate@v1",
                &codec::to_bytes_canonical(certificate).unwrap(),
                ctx,
            ))
            .unwrap();
        }
        for material in &materials {
            let receipt = material.to_recovery_share_receipt();
            run_async(registry.handle_service_call(
                &mut state,
                "publish_aft_recovery_share_receipt@v1",
                &codec::to_bytes_canonical(&receipt).unwrap(),
                ctx,
            ))
            .unwrap();
            run_async(registry.handle_service_call(
                &mut state,
                "publish_aft_recovery_share_material@v1",
                &codec::to_bytes_canonical(material).unwrap(),
                ctx,
            ))
            .unwrap();
        }
        run_async(registry.handle_service_call(
            &mut state,
            "publish_aft_recovered_publication_bundle@v1",
            &codec::to_bytes_canonical(&recovered).unwrap(),
            ctx,
        ))
        .unwrap();

        for certificate in &conflicting_certificates {
            run_async(registry.handle_service_call(
                &mut state,
                "publish_aft_recovery_witness_certificate@v1",
                &codec::to_bytes_canonical(certificate).unwrap(),
                ctx,
            ))
            .unwrap();
        }
        for material in &conflicting_materials {
            let receipt = material.to_recovery_share_receipt();
            run_async(registry.handle_service_call(
                &mut state,
                "publish_aft_recovery_share_receipt@v1",
                &codec::to_bytes_canonical(&receipt).unwrap(),
                ctx,
            ))
            .unwrap();
            run_async(registry.handle_service_call(
                &mut state,
                "publish_aft_recovery_share_material@v1",
                &codec::to_bytes_canonical(material).unwrap(),
                ctx,
            ))
            .unwrap();
        }
        run_async(registry.handle_service_call(
            &mut state,
            "publish_aft_recovered_publication_bundle@v1",
            &codec::to_bytes_canonical(&conflicting_recovered).unwrap(),
            ctx,
        ))
        .unwrap();
    });

    let abort = GuardianRegistry::load_canonical_order_abort(&state, recovered.height)
        .unwrap()
        .expect("conflicting recovered bundles should materialize an abort");
    assert_eq!(
        abort.reason,
        CanonicalOrderAbortReason::RecoverySupportConflict
    );
    assert!(
        GuardianRegistry::load_canonical_bulletin_close(&state, recovered.height)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        GuardianRegistry::load_recovered_publication_bundles(
            &state,
            recovered.height,
            &recovered.block_commitment_hash,
        )
        .unwrap(),
        vec![recovered.clone()]
    );
    assert_eq!(
        GuardianRegistry::load_recovered_publication_bundles(
            &state,
            conflicting_recovered.height,
            &conflicting_recovered.block_commitment_hash,
        )
        .unwrap(),
        vec![conflicting_recovered.clone()]
    );
}

fn publish_recovered_publication_fixture(
    registry: &GuardianRegistry,
    state: &mut MockState,
    capsule: &RecoveryCapsule,
    certificates: &[RecoveryWitnessCertificate],
    materials: &[RecoveryShareMaterial],
    recovered: &RecoveredPublicationBundle,
) {
    seed_previous_canonical_collapse_placeholder_if_absent(state, recovered.height, 0x90);
    with_ctx(|ctx| {
        run_async(registry.handle_service_call(
            state,
            "publish_aft_recovery_capsule@v1",
            &codec::to_bytes_canonical(capsule).unwrap(),
            ctx,
        ))
        .unwrap();
        for certificate in certificates {
            run_async(registry.handle_service_call(
                state,
                "publish_aft_recovery_witness_certificate@v1",
                &codec::to_bytes_canonical(certificate).unwrap(),
                ctx,
            ))
            .unwrap();
        }
        for material in materials {
            let receipt = material.to_recovery_share_receipt();
            run_async(registry.handle_service_call(
                state,
                "publish_aft_recovery_share_receipt@v1",
                &codec::to_bytes_canonical(&receipt).unwrap(),
                ctx,
            ))
            .unwrap();
            run_async(registry.handle_service_call(
                state,
                "publish_aft_recovery_share_material@v1",
                &codec::to_bytes_canonical(material).unwrap(),
                ctx,
            ))
            .unwrap();
        }
        run_async(registry.handle_service_call(
            state,
            "publish_aft_recovered_publication_bundle@v1",
            &codec::to_bytes_canonical(recovered).unwrap(),
            ctx,
        ))
        .unwrap();
    });
}
