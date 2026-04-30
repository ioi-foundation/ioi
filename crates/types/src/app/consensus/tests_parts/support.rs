use super::*;

use super::{
    archived_recovered_restart_page_range, bind_canonical_collapse_continuity,
    build_archived_recovered_history_checkpoint,
    build_archived_recovered_history_profile_activation,
    build_archived_recovered_history_retention_receipt, build_archived_recovered_history_segment,
    build_archived_recovered_restart_page, build_bulletin_custody_assignment,
    build_bulletin_custody_response, build_canonical_bulletin_close,
    build_committed_surface_canonical_order_certificate, build_publication_frontier,
    build_reference_canonical_order_certificate,
    canonical_archived_recovered_history_checkpoint_hash,
    canonical_archived_recovered_history_profile_activation_hash,
    canonical_archived_recovered_history_segment_hash,
    canonical_archived_recovered_history_segment_root,
    canonical_archived_recovered_restart_page_hash,
    canonical_bulletin_availability_certificate_hash,
    canonical_bulletin_close_eq_ignoring_retrievability_anchor,
    canonical_bulletin_close_retrievability_anchor, canonical_bulletin_commitment_hash,
    canonical_bulletin_custody_assignment_hash, canonical_bulletin_custody_receipt_hash,
    canonical_bulletin_custody_response_hash, canonical_bulletin_retrievability_challenge_hash,
    canonical_collapse_commitment_hash_from_object, canonical_collapse_eq_on_header_surface,
    canonical_collapse_extension_certificate, canonical_collapse_historical_continuation_anchor,
    canonical_collapse_object_hash, canonical_collapse_payload_hash,
    canonical_collapse_recursive_proof_hash, canonical_missing_recovery_share_hash,
    canonical_order_certificate_hash, canonical_order_publication_bundle_hash,
    canonical_recoverable_slot_payload_hash, canonical_recoverable_slot_payload_v2_hash,
    canonical_recoverable_slot_payload_v3_hash, canonical_recoverable_slot_payload_v4_hash,
    canonical_recoverable_slot_payload_v5_hash, canonical_recovered_publication_bundle_hash,
    canonical_recovery_capsule_hash, canonical_recovery_share_material_hash,
    canonical_recovery_share_receipt_hash, canonical_recovery_witness_certificate_hash,
    canonical_replay_prefix_historical_continuation_anchor, canonical_transaction_root_from_hashes,
    canonicalize_transactions_for_header, derive_canonical_collapse_object,
    derive_canonical_collapse_object_from_recovered_surface,
    derive_canonical_collapse_object_with_previous, derive_canonical_order_execution_object,
    derive_canonical_order_public_obstruction, encode_coded_recovery_shards,
    expected_previous_canonical_collapse_commitment_hash, extract_canonical_bulletin_surface,
    extract_endogenous_canonical_bulletin_surface, lift_recoverable_slot_payload_v3_to_v4,
    lift_recoverable_slot_payload_v4_to_v5,
    normalize_recovered_publication_bundle_supporting_witnesses,
    recover_canonical_order_publication_bundle_from_share_materials,
    recover_recoverable_slot_payload_v3_from_share_materials,
    set_canonical_bulletin_close_retrievability_anchor,
    validate_archived_recovered_history_segment_predecessor,
    validate_bulletin_retrievability_challenge, verify_block_header_canonical_collapse_evidence,
    verify_bulletin_surface_publication, verify_canonical_collapse_continuity,
    verify_canonical_collapse_recursive_proof,
    verify_canonical_collapse_recursive_proof_matches_collapse, verify_canonical_order_certificate,
    verify_canonical_order_publication_bundle, verify_publication_frontier,
    verify_publication_frontier_contradiction, CanonicalCollapseContinuityProofSystem,
    CanonicalCollapseKind, CanonicalOrderAbortReason, PublicationFrontierContradiction,
    PublicationFrontierContradictionKind,
};
use crate::app::{
    build_archived_recovered_history_profile, canonical_archived_recovered_history_profile_hash,
    canonical_archived_recovered_history_retention_receipt_hash,
    canonical_assigned_recovery_share_envelope_hash,
    canonical_asymptote_observer_canonical_close_hash,
    canonical_asymptote_observer_challenges_hash, canonical_asymptote_observer_transcripts_hash,
    canonical_validator_sets_hash, to_root_hash, AccountId, ArchivedRecoveredHistoryCheckpoint,
    ArchivedRecoveredHistoryCheckpointUpdateRule, ArchivedRecoveredHistorySegment,
    ArchivedRecoveredRestartPage, AssignedRecoveryShareEnvelopeV1, AsymptoteObserverCanonicalClose,
    BlockHeader, BulletinAvailabilityCertificate, BulletinCommitment, BulletinCustodyAssignment,
    BulletinCustodyResponse, BulletinRetrievabilityChallenge, BulletinRetrievabilityChallengeKind,
    BulletinSurfaceEntry, CanonicalBulletinClose, CanonicalCollapseExtensionCertificate,
    CanonicalCollapseObject, CanonicalOrderCertificate, CanonicalOrderPublicationBundle,
    CanonicalOrderingCollapse, CanonicalReplayPrefixEntry, ChainId, ChainTransaction,
    CollapseState, FinalityTier, GuardianWitnessRecoveryBinding, MissingRecoveryShare,
    OmissionProof, QuorumCertificate, RecoverableSlotPayloadV1, RecoverableSlotPayloadV2,
    RecoverableSlotPayloadV3, RecoverableSlotPayloadV4, RecoverableSlotPayloadV5,
    RecoveredCanonicalHeaderEntry, RecoveredCertifiedHeaderEntry, RecoveredPublicationBundle,
    RecoveredRestartBlockHeaderEntry, RecoveryCapsule, RecoveryCodingDescriptor,
    RecoveryCodingFamily, RecoveryShareMaterial, RecoveryShareReceipt, RecoveryWitnessCertificate,
    SealedFinalityProof, SignHeader, SignatureProof, SignatureSuite, StateRoot, SystemPayload,
    SystemTransaction, ValidatorSetV1, ValidatorSetsV1, ValidatorV1,
};
use crate::codec;
use std::sync::{Mutex, OnceLock};

fn sample_archived_recovered_history_profile_for_tests(
) -> crate::app::ArchivedRecoveredHistoryProfile {
    build_archived_recovered_history_profile(
        1024,
        5,
        2,
        5,
        4,
        ArchivedRecoveredHistoryCheckpointUpdateRule::EveryPublishedSegmentV1,
    )
    .expect("archived recovered-history profile")
}

fn sample_archived_recovered_history_profile_hash_for_tests() -> [u8; 32] {
    canonical_archived_recovered_history_profile_hash(
        &sample_archived_recovered_history_profile_for_tests(),
    )
    .expect("archived recovered-history profile hash")
}

fn sample_archived_recovered_history_profile_activation_for_tests(
) -> crate::app::ArchivedRecoveredHistoryProfileActivation {
    build_archived_recovered_history_profile_activation(
        &sample_archived_recovered_history_profile_for_tests(),
        None,
        1,
        None,
    )
    .expect("archived recovered-history profile activation")
}

fn sample_archived_recovered_history_profile_activation_hash_for_tests() -> [u8; 32] {
    canonical_archived_recovered_history_profile_activation_hash(
        &sample_archived_recovered_history_profile_activation_for_tests(),
    )
    .expect("archived recovered-history profile activation hash")
}

fn sample_validator_set_for_retrievability_tests() -> ValidatorSetV1 {
    ValidatorSetV1 {
        effective_from_height: 1,
        total_weight: 3,
        validators: vec![
            ValidatorV1 {
                account_id: AccountId([0x11; 32]),
                weight: 1,
                consensus_key: Default::default(),
            },
            ValidatorV1 {
                account_id: AccountId([0x12; 32]),
                weight: 1,
                consensus_key: Default::default(),
            },
            ValidatorV1 {
                account_id: AccountId([0x13; 32]),
                weight: 1,
                consensus_key: Default::default(),
            },
            ValidatorV1 {
                account_id: AccountId([0x14; 32]),
                weight: 1,
                consensus_key: Default::default(),
            },
            ValidatorV1 {
                account_id: AccountId([0x15; 32]),
                weight: 1,
                consensus_key: Default::default(),
            },
        ],
    }
}

fn sample_bulletin_custody_plane(
    certificate: &CanonicalOrderCertificate,
    entries: &[BulletinSurfaceEntry],
) -> (
    crate::app::BulletinRetrievabilityProfile,
    crate::app::BulletinShardManifest,
    ValidatorSetV1,
    BulletinCustodyAssignment,
    crate::app::BulletinCustodyReceipt,
    BulletinCustodyResponse,
) {
    let profile = super::build_bulletin_retrievability_profile(
        &certificate.bulletin_commitment,
        &certificate.bulletin_availability_certificate,
    )
    .expect("build profile");
    let manifest = super::build_bulletin_shard_manifest(
        &certificate.bulletin_commitment,
        &certificate.bulletin_availability_certificate,
        &profile,
        entries,
    )
    .expect("build manifest");
    let validator_set = sample_validator_set_for_retrievability_tests();
    let assignment = build_bulletin_custody_assignment(&profile, &manifest, &validator_set)
        .expect("build custody assignment");
    let receipt =
        super::build_bulletin_custody_receipt(&profile, &manifest).expect("build receipt");
    let response = build_bulletin_custody_response(
        &certificate.bulletin_commitment,
        &profile,
        &manifest,
        &assignment,
        &receipt,
        entries,
    )
    .expect("build custody response");
    (
        profile,
        manifest,
        validator_set,
        assignment,
        receipt,
        response,
    )
}

fn certificate_from_predecessor(
    predecessor: &CanonicalCollapseObject,
) -> CanonicalCollapseExtensionCertificate {
    canonical_collapse_extension_certificate(predecessor.height + 1, predecessor)
        .expect("extension certificate")
}

fn sample_canonical_collapse_object(
    height: u64,
    previous: Option<&CanonicalCollapseObject>,
    seed: u8,
) -> CanonicalCollapseObject {
    let mut collapse = CanonicalCollapseObject {
        height,
        previous_canonical_collapse_commitment_hash: [0u8; 32],
        continuity_accumulator_hash: [0u8; 32],
        continuity_recursive_proof: Default::default(),
        ordering: CanonicalOrderingCollapse {
            height,
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
    bind_canonical_collapse_continuity(&mut collapse, previous)
        .expect("bind canonical collapse continuity");
    collapse
}

fn sample_ordering_header(height: u64, view: u64, seed: u8) -> BlockHeader {
    BlockHeader {
        height,
        view,
        parent_hash: [seed.wrapping_add(1); 32],
        parent_state_root: StateRoot(vec![seed.wrapping_add(2); 32]),
        state_root: StateRoot(vec![seed.wrapping_add(3); 32]),
        transactions_root: vec![],
        timestamp: 1_750_000_000 + height,
        timestamp_ms: (1_750_000_000 + height) * 1_000,
        gas_used: 0,
        validator_set: Vec::new(),
        producer_account_id: AccountId([seed.wrapping_add(4); 32]),
        producer_key_suite: SignatureSuite::ED25519,
        producer_pubkey_hash: [seed.wrapping_add(5); 32],
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
    }
}

fn sample_ordering_transactions(seed: u8) -> Vec<ChainTransaction> {
    vec![
        ChainTransaction::System(Box::new(SystemTransaction {
            header: SignHeader {
                account_id: AccountId([seed.wrapping_add(10); 32]),
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
        })),
        ChainTransaction::System(Box::new(SystemTransaction {
            header: SignHeader {
                account_id: AccountId([seed.wrapping_add(11); 32]),
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
        })),
    ]
}

fn sample_committed_surface_ordering_fixture(
    height: u64,
    view: u64,
    seed: u8,
) -> (
    BlockHeader,
    Vec<ChainTransaction>,
    CanonicalOrderCertificate,
) {
    let mut header = sample_ordering_header(height, view, seed);
    let transactions =
        canonicalize_transactions_for_header(&header, &sample_ordering_transactions(seed))
            .expect("canonicalized transactions");
    let tx_hashes: Vec<[u8; 32]> = transactions
        .iter()
        .map(|tx| tx.hash().expect("tx hash"))
        .collect();
    header.transactions_root =
        canonical_transaction_root_from_hashes(&tx_hashes).expect("transactions root");
    let certificate = build_committed_surface_canonical_order_certificate(&header, &transactions)
        .expect("build committed-surface certificate");
    header.canonical_order_certificate = Some(certificate.clone());
    (header, transactions, certificate)
}

fn build_sample_recoverable_slot_payload_v3(
    height: u64,
    view: u64,
    seed: u8,
) -> (RecoverableSlotPayloadV3, CanonicalOrderPublicationBundle) {
    let (mut header, ordered_transactions, certificate) =
        sample_committed_surface_ordering_fixture(height, view, seed);
    header.canonical_order_certificate = Some(certificate.clone());
    let execution_object = derive_canonical_order_execution_object(&header, &ordered_transactions)
        .expect("derive canonical order execution object");
    let bundle = CanonicalOrderPublicationBundle {
        bulletin_commitment: execution_object.bulletin_commitment.clone(),
        bulletin_entries: execution_object.bulletin_entries.clone(),
        bulletin_availability_certificate: execution_object
            .bulletin_availability_certificate
            .clone(),
        bulletin_retrievability_profile: execution_object.bulletin_retrievability_profile.clone(),
        bulletin_shard_manifest: execution_object.bulletin_shard_manifest.clone(),
        bulletin_custody_receipt: execution_object.bulletin_custody_receipt.clone(),
        canonical_order_certificate: execution_object.canonical_order_certificate.clone(),
    };
    let payload = RecoverableSlotPayloadV3 {
        height: header.height,
        view: header.view,
        producer_account_id: header.producer_account_id,
        block_commitment_hash: header
            .hash()
            .expect("header hash")
            .as_slice()
            .try_into()
            .expect("32-byte block hash"),
        parent_block_hash: header.parent_hash,
        canonical_order_certificate: certificate,
        ordered_transaction_bytes: ordered_transactions
            .iter()
            .map(|transaction| {
                codec::to_bytes_canonical(transaction).expect("encode ordered transaction")
            })
            .collect(),
        canonical_order_publication_bundle_bytes: codec::to_bytes_canonical(&bundle)
            .expect("encode publication bundle"),
    };
    (payload, bundle)
}

fn build_sample_recoverable_slot_payload_v4(
    height: u64,
    view: u64,
    seed: u8,
) -> (
    RecoverableSlotPayloadV4,
    CanonicalOrderPublicationBundle,
    CanonicalBulletinClose,
) {
    let (payload_v3, bundle) = build_sample_recoverable_slot_payload_v3(height, view, seed);
    let (payload_v4, lifted_bundle, bulletin_close) =
        lift_recoverable_slot_payload_v3_to_v4(&payload_v3).expect("lift recoverable payload v4");
    assert_eq!(lifted_bundle, bundle);
    (payload_v4, bundle, bulletin_close)
}

fn build_sample_recoverable_slot_payload_v5(
    height: u64,
    view: u64,
    seed: u8,
) -> (
    RecoverableSlotPayloadV5,
    CanonicalOrderPublicationBundle,
    CanonicalBulletinClose,
    Vec<BulletinSurfaceEntry>,
) {
    let (payload_v4, bundle, bulletin_close) =
        build_sample_recoverable_slot_payload_v4(height, view, seed);
    let (payload_v5, lifted_bundle, lifted_close, surface) =
        lift_recoverable_slot_payload_v4_to_v5(&payload_v4).expect("lift recoverable payload v5");
    assert_eq!(lifted_bundle, bundle);
    assert_eq!(lifted_close, bulletin_close);
    (payload_v5, bundle, bulletin_close, surface)
}

fn encode_systematic_xor_k_of_k_plus_1_shards(
    payload: &RecoverableSlotPayloadV3,
    recovery_threshold: u16,
) -> Vec<Vec<u8>> {
    encode_coded_recovery_shards(
        xor_recovery_coding(recovery_threshold + 1, recovery_threshold),
        &codec::to_bytes_canonical(payload).expect("encode payload"),
    )
    .expect("encode xor shards")
}

fn encode_systematic_gf256_k_of_n_shards(
    payload: &RecoverableSlotPayloadV3,
    share_count: usize,
    recovery_threshold: usize,
) -> Vec<Vec<u8>> {
    encode_coded_recovery_shards(
        gf256_recovery_coding(
            u16::try_from(share_count).expect("share count"),
            u16::try_from(recovery_threshold).expect("recovery threshold"),
        ),
        &codec::to_bytes_canonical(payload).expect("encode payload"),
    )
    .expect("encode gf256 shards")
}

fn encode_systematic_gf256_2_of_4_shards(payload: &RecoverableSlotPayloadV3) -> Vec<Vec<u8>> {
    encode_systematic_gf256_k_of_n_shards(payload, 4, 2)
}

fn encode_systematic_gf256_3_of_5_shards(payload: &RecoverableSlotPayloadV3) -> Vec<Vec<u8>> {
    encode_systematic_gf256_k_of_n_shards(payload, 5, 3)
}

fn encode_systematic_gf256_3_of_7_shards(payload: &RecoverableSlotPayloadV3) -> Vec<Vec<u8>> {
    encode_systematic_gf256_k_of_n_shards(payload, 7, 3)
}

fn encode_systematic_gf256_4_of_6_shards(payload: &RecoverableSlotPayloadV3) -> Vec<Vec<u8>> {
    encode_systematic_gf256_k_of_n_shards(payload, 6, 4)
}

fn encode_systematic_gf256_4_of_7_shards(payload: &RecoverableSlotPayloadV3) -> Vec<Vec<u8>> {
    encode_systematic_gf256_k_of_n_shards(payload, 7, 4)
}

fn transparent_recovery_coding(
    share_count: u16,
    recovery_threshold: u16,
) -> RecoveryCodingDescriptor {
    RecoveryCodingDescriptor {
        family: RecoveryCodingFamily::TransparentCommittedSurfaceV1,
        share_count,
        recovery_threshold,
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

fn continuity_env_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn collect_index_combinations(total: usize, choose: usize) -> Vec<Vec<usize>> {
    fn recurse(
        total: usize,
        choose: usize,
        start: usize,
        current: &mut Vec<usize>,
        all: &mut Vec<Vec<usize>>,
    ) {
        if current.len() == choose {
            all.push(current.clone());
            return;
        }
        let remaining = choose.saturating_sub(current.len());
        for index in start..=total.saturating_sub(remaining) {
            current.push(index);
            recurse(total, choose, index + 1, current, all);
            current.pop();
        }
    }

    if choose == 0 {
        return vec![Vec::new()];
    }
    let mut all = Vec::new();
    let mut current = Vec::new();
    recurse(total, choose, 0, &mut current, &mut all);
    all
}

fn select_recovery_share_materials(
    materials: &[RecoveryShareMaterial],
    indices: &[usize],
) -> Vec<RecoveryShareMaterial> {
    indices
        .iter()
        .map(|index| materials[*index].clone())
        .collect()
}

fn build_coded_recovery_materials_for_contract(
    payload: &RecoverableSlotPayloadV3,
    coding: RecoveryCodingDescriptor,
    seed: u8,
) -> Vec<RecoveryShareMaterial> {
    let payload_bytes = codec::to_bytes_canonical(payload).expect("encode payload");
    let shards = coding
        .family_contract()
        .expect("coded recovery-family contract")
        .encode_payload_shards(&payload_bytes)
        .expect("encode payload shards");
    shards
        .into_iter()
        .enumerate()
        .map(|(share_index, material_bytes)| RecoveryShareMaterial {
            height: payload.height,
            witness_manifest_hash: [seed.wrapping_add(share_index as u8 + 1); 32],
            block_commitment_hash: payload.block_commitment_hash,
            coding,
            share_index: u16::try_from(share_index).expect("share index"),
            share_commitment_hash: [seed.wrapping_add(share_index as u8 + 41); 32],
            material_bytes,
        })
        .collect()
}

fn assert_coded_recovery_family_contract_conformance_case(
    height: u64,
    view: u64,
    seed: u8,
    coding: RecoveryCodingDescriptor,
) {
    let contract = coding
        .family_contract()
        .expect("coded recovery-family contract");
    assert!(
        contract.supports_coded_payload_reconstruction(),
        "test harness requires a coded recovery-family contract"
    );
    let (payload, expected_bundle) = build_sample_recoverable_slot_payload_v3(height, view, seed);
    let materials =
        build_coded_recovery_materials_for_contract(&payload, coding, seed.wrapping_add(60));

    for indices in
        collect_index_combinations(materials.len(), usize::from(coding.recovery_threshold))
    {
        let subset = select_recovery_share_materials(&materials, &indices);
        let recovered_payload_bytes = contract
            .recover_payload_bytes_from_materials(&subset)
            .unwrap_or_else(|error| {
                panic!(
                    "threshold subset {indices:?} should reconstruct under {}: {error}",
                    coding.label()
                )
            });
        let recovered_payload: RecoverableSlotPayloadV3 =
            codec::from_bytes_canonical(&recovered_payload_bytes)
                .expect("decode reconstructed payload");
        let recovered_top_level = recover_recoverable_slot_payload_v3_from_share_materials(&subset)
            .unwrap_or_else(|error| {
                panic!(
                    "top-level threshold subset {indices:?} should reconstruct under {}: {error}",
                    coding.label()
                )
            });
        let (recovered_bundle_payload, recovered_bundle) =
                recover_canonical_order_publication_bundle_from_share_materials(&subset)
                    .unwrap_or_else(|error| {
                        panic!(
                            "publication bundle threshold subset {indices:?} should reconstruct under {}: {error}",
                            coding.label()
                        )
                    });
        assert_eq!(recovered_payload, payload);
        assert_eq!(recovered_top_level, payload);
        assert_eq!(recovered_bundle_payload, payload);
        assert_eq!(recovered_bundle, expected_bundle);
    }

    for indices in collect_index_combinations(
        materials.len(),
        usize::from(coding.recovery_threshold.saturating_sub(1)),
    ) {
        let subset = select_recovery_share_materials(&materials, &indices);
        let error = contract
            .recover_payload_bytes_from_materials(&subset)
            .expect_err("below-threshold subset should fail under the contract");
        assert!(
            error.contains(&format!(
                "requires at least {} distinct share reveals",
                coding.recovery_threshold
            )),
            "unexpected below-threshold error for {} subset {indices:?}: {error}",
            coding.label()
        );
    }
}

