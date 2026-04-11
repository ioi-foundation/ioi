    use super::{
        archived_recovered_restart_page_range, bind_canonical_collapse_continuity,
        build_archived_recovered_history_checkpoint,
        build_archived_recovered_history_profile_activation,
        build_archived_recovered_history_retention_receipt,
        build_archived_recovered_history_segment, build_archived_recovered_restart_page,
        build_canonical_bulletin_close, build_committed_surface_canonical_order_certificate,
        build_publication_frontier, build_reference_canonical_order_certificate,
        canonical_archived_recovered_history_checkpoint_hash,
        canonical_archived_recovered_history_profile_activation_hash,
        canonical_archived_recovered_history_segment_hash,
        canonical_archived_recovered_history_segment_root,
        canonical_archived_recovered_restart_page_hash,
        canonical_bulletin_availability_certificate_hash,
        canonical_bulletin_custody_assignment_hash, canonical_bulletin_custody_receipt_hash,
        canonical_bulletin_custody_response_hash,
        canonical_bulletin_close_eq_ignoring_retrievability_anchor,
        canonical_bulletin_close_retrievability_anchor,
        canonical_bulletin_commitment_hash,
        canonical_bulletin_retrievability_challenge_hash,
        canonical_collapse_commitment_hash_from_object, canonical_collapse_extension_certificate,
        canonical_collapse_eq_on_header_surface, canonical_collapse_payload_hash,
        canonical_collapse_historical_continuation_anchor, canonical_collapse_object_hash,
        canonical_collapse_recursive_proof_hash, canonical_missing_recovery_share_hash,
        canonical_order_certificate_hash, canonical_order_publication_bundle_hash,
        canonical_recoverable_slot_payload_hash, canonical_recoverable_slot_payload_v2_hash,
        canonical_recoverable_slot_payload_v3_hash, canonical_recoverable_slot_payload_v4_hash,
        canonical_recoverable_slot_payload_v5_hash, canonical_recovered_publication_bundle_hash,
        canonical_recovery_capsule_hash, canonical_recovery_share_material_hash,
        canonical_recovery_share_receipt_hash, canonical_recovery_witness_certificate_hash,
        canonical_replay_prefix_historical_continuation_anchor,
        canonical_transaction_root_from_hashes, canonicalize_transactions_for_header,
        derive_canonical_collapse_object, derive_canonical_collapse_object_from_recovered_surface,
        derive_canonical_collapse_object_with_previous, derive_canonical_order_execution_object,
        derive_canonical_order_public_obstruction, encode_coded_recovery_shards,
        expected_previous_canonical_collapse_commitment_hash,
        extract_canonical_bulletin_surface, extract_endogenous_canonical_bulletin_surface,
        lift_recoverable_slot_payload_v3_to_v4, lift_recoverable_slot_payload_v4_to_v5,
        normalize_recovered_publication_bundle_supporting_witnesses,
        recover_canonical_order_publication_bundle_from_share_materials,
        recover_recoverable_slot_payload_v3_from_share_materials,
        set_canonical_bulletin_close_retrievability_anchor,
        build_bulletin_custody_assignment, build_bulletin_custody_response,
        validate_bulletin_retrievability_challenge,
        validate_archived_recovered_history_segment_predecessor,
        verify_block_header_canonical_collapse_evidence, verify_bulletin_surface_publication,
        verify_canonical_collapse_continuity, verify_canonical_collapse_recursive_proof,
        verify_canonical_collapse_recursive_proof_matches_collapse,
        verify_canonical_order_certificate, verify_canonical_order_publication_bundle,
        verify_publication_frontier, verify_publication_frontier_contradiction,
        CanonicalCollapseContinuityProofSystem, CanonicalCollapseKind, CanonicalOrderAbortReason,
        PublicationFrontierContradiction, PublicationFrontierContradictionKind,
    };
    use crate::app::{
        build_archived_recovered_history_profile,
        canonical_archived_recovered_history_profile_hash,
        canonical_archived_recovered_history_retention_receipt_hash,
        canonical_assigned_recovery_share_envelope_hash,
        canonical_asymptote_observer_canonical_close_hash,
        canonical_asymptote_observer_challenges_hash,
        canonical_asymptote_observer_transcripts_hash, canonical_validator_sets_hash, to_root_hash,
        AccountId, ArchivedRecoveredHistoryCheckpoint,
        ArchivedRecoveredHistoryCheckpointUpdateRule, ArchivedRecoveredHistorySegment,
        ArchivedRecoveredRestartPage, AssignedRecoveryShareEnvelopeV1,
        AsymptoteObserverCanonicalClose, BlockHeader, BulletinAvailabilityCertificate,
        BulletinCommitment, BulletinCustodyAssignment, BulletinCustodyResponse,
        BulletinRetrievabilityChallenge,
        BulletinRetrievabilityChallengeKind, BulletinSurfaceEntry, CanonicalBulletinClose,
        CanonicalCollapseExtensionCertificate, CanonicalCollapseObject, CanonicalOrderCertificate,
        CanonicalOrderPublicationBundle, CanonicalOrderingCollapse, CanonicalReplayPrefixEntry,
        ChainId, ChainTransaction, CollapseState, FinalityTier, GuardianWitnessRecoveryBinding,
        MissingRecoveryShare, OmissionProof, QuorumCertificate, RecoverableSlotPayloadV1,
        RecoverableSlotPayloadV2, RecoverableSlotPayloadV3, RecoverableSlotPayloadV4,
        RecoverableSlotPayloadV5, RecoveredCanonicalHeaderEntry, RecoveredCertifiedHeaderEntry,
        RecoveredPublicationBundle, RecoveredRestartBlockHeaderEntry, RecoveryCapsule,
        RecoveryCodingDescriptor, RecoveryCodingFamily, RecoveryShareMaterial,
        RecoveryShareReceipt, RecoveryWitnessCertificate, SealedFinalityProof, SignHeader,
        SignatureProof, SignatureSuite, StateRoot, SystemPayload, SystemTransaction,
        ValidatorSetV1, ValidatorSetsV1, ValidatorV1,
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
        (profile, manifest, validator_set, assignment, receipt, response)
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
        let certificate =
            build_committed_surface_canonical_order_certificate(&header, &transactions)
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
        let execution_object =
            derive_canonical_order_execution_object(&header, &ordered_transactions)
                .expect("derive canonical order execution object");
        let bundle = CanonicalOrderPublicationBundle {
            bulletin_commitment: execution_object.bulletin_commitment.clone(),
            bulletin_entries: execution_object.bulletin_entries.clone(),
            bulletin_availability_certificate: execution_object
                .bulletin_availability_certificate
                .clone(),
            bulletin_retrievability_profile: execution_object
                .bulletin_retrievability_profile
                .clone(),
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
            lift_recoverable_slot_payload_v3_to_v4(&payload_v3)
                .expect("lift recoverable payload v4");
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
            lift_recoverable_slot_payload_v4_to_v5(&payload_v4)
                .expect("lift recoverable payload v5");
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

    fn gf256_recovery_coding(
        share_count: u16,
        recovery_threshold: u16,
    ) -> RecoveryCodingDescriptor {
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
        let (payload, expected_bundle) =
            build_sample_recoverable_slot_payload_v3(height, view, seed);
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
            let recovered_top_level = recover_recoverable_slot_payload_v3_from_share_materials(
                &subset,
            )
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

    #[test]
    fn reference_canonical_order_certificate_verifies_for_empty_block() {
        let header = BlockHeader {
            height: 7,
            view: 2,
            parent_hash: [9u8; 32],
            parent_state_root: StateRoot(vec![1u8; 32]),
            state_root: StateRoot(vec![2u8; 32]),
            transactions_root: vec![3u8; 32],
            timestamp: 1_750_000_123,
            timestamp_ms: 1_750_000_123_000,
            gas_used: 0,
            validator_set: Vec::new(),
            producer_account_id: AccountId([4u8; 32]),
            producer_key_suite: SignatureSuite::ED25519,
            producer_pubkey_hash: [5u8; 32],
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

        let certificate =
            build_reference_canonical_order_certificate(&header, &[]).expect("build certificate");
        assert!(certificate.omission_proofs.is_empty());
        assert_ne!(certificate.bulletin_commitment.bulletin_root, [0u8; 32]);
        let bulletin_close = build_canonical_bulletin_close(
            &certificate.bulletin_commitment,
            &certificate.bulletin_availability_certificate,
        )
        .expect("build bulletin close");
        verify_canonical_order_certificate(
            &header,
            &certificate,
            Some(&certificate.bulletin_commitment),
            Some(&certificate.bulletin_availability_certificate),
            Some(&bulletin_close),
        )
        .expect("verify canonical order certificate");
    }

    #[test]
    fn committed_surface_canonical_order_certificate_verifies_for_canonical_block() {
        let base_header = BlockHeader {
            height: 11,
            view: 4,
            parent_hash: [19u8; 32],
            parent_state_root: StateRoot(vec![1u8; 32]),
            state_root: StateRoot(vec![2u8; 32]),
            transactions_root: vec![],
            timestamp: 1_750_000_777,
            timestamp_ms: 1_750_000_777_000,
            gas_used: 0,
            validator_set: Vec::new(),
            producer_account_id: AccountId([4u8; 32]),
            producer_key_suite: SignatureSuite::ED25519,
            producer_pubkey_hash: [5u8; 32],
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
                account_id: AccountId([12u8; 32]),
                nonce: 1,
                chain_id: ChainId(1),
                tx_version: 1,
                session_auth: None,
            },
            payload: SystemPayload::CallService {
                service_id: "guardian_registry".into(),
                method: "publish_aft_bulletin_commitment@v1".into(),
                params: vec![3],
            },
            signature_proof: SignatureProof::default(),
        }));
        let tx_two = ChainTransaction::System(Box::new(SystemTransaction {
            header: SignHeader {
                account_id: AccountId([13u8; 32]),
                nonce: 1,
                chain_id: ChainId(1),
                tx_version: 1,
                session_auth: None,
            },
            payload: SystemPayload::CallService {
                service_id: "guardian_registry".into(),
                method: "publish_aft_canonical_order_artifact_bundle@v1".into(),
                params: vec![4],
            },
            signature_proof: SignatureProof::default(),
        }));

        let ordered_transactions =
            canonicalize_transactions_for_header(&base_header, &[tx_one, tx_two])
                .expect("canonicalized transactions");
        let tx_hashes: Vec<[u8; 32]> = ordered_transactions
            .iter()
            .map(|tx| tx.hash().expect("tx hash"))
            .collect();

        let mut header = base_header;
        header.transactions_root =
            canonical_transaction_root_from_hashes(&tx_hashes).expect("transactions root");

        let certificate =
            build_committed_surface_canonical_order_certificate(&header, &ordered_transactions)
                .expect("build committed-surface certificate");
        let bulletin_close = build_canonical_bulletin_close(
            &certificate.bulletin_commitment,
            &certificate.bulletin_availability_certificate,
        )
        .expect("build bulletin close");
        verify_canonical_order_certificate(
            &header,
            &certificate,
            Some(&certificate.bulletin_commitment),
            Some(&certificate.bulletin_availability_certificate),
            Some(&bulletin_close),
        )
        .expect("verify committed-surface certificate");
        let entries = super::build_bulletin_surface_entries(header.height, &ordered_transactions)
            .expect("build bulletin surface entries");
        verify_bulletin_surface_publication(&certificate, &entries)
            .expect("verify bulletin surface publication");
        let extracted = extract_canonical_bulletin_surface(
            &bulletin_close,
            &certificate.bulletin_commitment,
            &certificate.bulletin_availability_certificate,
            &entries,
        )
        .expect("extract bulletin surface");
        assert_eq!(extracted, entries);
        assert!(
            canonical_bulletin_close_retrievability_anchor(&bulletin_close)
                .expect("read unanchored close anchor")
                .is_none()
        );
        let rebuilt_close =
            verify_canonical_order_publication_bundle(&super::CanonicalOrderPublicationBundle {
                bulletin_commitment: certificate.bulletin_commitment.clone(),
                bulletin_entries: entries.clone(),
                bulletin_availability_certificate: certificate
                    .bulletin_availability_certificate
                    .clone(),
                bulletin_retrievability_profile: super::build_bulletin_retrievability_profile(
                    &certificate.bulletin_commitment,
                    &certificate.bulletin_availability_certificate,
                )
                .expect("build retrievability profile"),
                bulletin_shard_manifest: {
                    let profile = super::build_bulletin_retrievability_profile(
                        &certificate.bulletin_commitment,
                        &certificate.bulletin_availability_certificate,
                    )
                    .expect("build retrievability profile");
                    super::build_bulletin_shard_manifest(
                        &certificate.bulletin_commitment,
                        &certificate.bulletin_availability_certificate,
                        &profile,
                        &entries,
                    )
                    .expect("build shard manifest")
                },
                bulletin_custody_receipt: {
                    let profile = super::build_bulletin_retrievability_profile(
                        &certificate.bulletin_commitment,
                        &certificate.bulletin_availability_certificate,
                    )
                    .expect("build retrievability profile");
                    let manifest = super::build_bulletin_shard_manifest(
                        &certificate.bulletin_commitment,
                        &certificate.bulletin_availability_certificate,
                        &profile,
                        &entries,
                    )
                    .expect("build shard manifest");
                    super::build_bulletin_custody_receipt(&profile, &manifest)
                        .expect("build custody receipt")
                },
                canonical_order_certificate: certificate.clone(),
            })
            .expect("verify publication bundle");
        assert!(canonical_bulletin_close_eq_ignoring_retrievability_anchor(
            &rebuilt_close,
            &bulletin_close
        ));
        assert!(
            canonical_bulletin_close_retrievability_anchor(&rebuilt_close)
                .expect("read anchored close anchor")
                .is_some()
        );
        let (profile, manifest, validator_set, assignment, receipt, response) =
            sample_bulletin_custody_plane(&certificate, &entries);
        let endogenous_extracted = extract_endogenous_canonical_bulletin_surface(
            &rebuilt_close,
            &certificate.bulletin_commitment,
            &certificate.bulletin_availability_certificate,
            &profile,
            &manifest,
            &assignment,
            &receipt,
            &response,
            &entries,
            &validator_set,
        )
        .expect("extract endogenous bulletin surface");
        assert_eq!(endogenous_extracted, entries);

        header.canonical_order_certificate = Some(certificate.clone());
        let execution_object =
            derive_canonical_order_execution_object(&header, &ordered_transactions)
                .expect("derive canonical order execution object");
        assert_eq!(
            execution_object.bulletin_commitment,
            certificate.bulletin_commitment
        );
        assert_eq!(
            execution_object.bulletin_availability_certificate,
            certificate.bulletin_availability_certificate
        );
        assert_eq!(execution_object.bulletin_close, rebuilt_close);
        assert_eq!(execution_object.canonical_order_certificate, certificate);
        assert_eq!(execution_object.bulletin_entries, entries);
    }

    #[test]
    fn canonical_collapse_header_surface_equality_ignores_materialized_ordering_bundle_fields() {
        let mut header = BlockHeader {
            height: 1,
            view: 0,
            parent_hash: [1u8; 32],
            parent_state_root: StateRoot(vec![2u8; 32]),
            state_root: StateRoot(vec![3u8; 32]),
            transactions_root: vec![4u8; 32],
            timestamp: 1_750_000_123,
            timestamp_ms: 1_750_000_123_000,
            gas_used: 7,
            validator_set: vec![vec![5u8; 32]],
            producer_account_id: AccountId([6u8; 32]),
            producer_key_suite: SignatureSuite::ED25519,
            producer_pubkey_hash: [7u8; 32],
            producer_pubkey: vec![8u8; 32],
            oracle_counter: 0,
            oracle_trace_hash: [9u8; 32],
            guardian_certificate: None,
            sealed_finality_proof: None,
            canonical_order_certificate: None,
            timeout_certificate: None,
            parent_qc: QuorumCertificate::default(),
            previous_canonical_collapse_commitment_hash: [0u8; 32],
            canonical_collapse_extension_certificate: None,
            publication_frontier: None,
            signature: vec![10u8; 64],
        };
        header.canonical_order_certificate = Some(
            build_reference_canonical_order_certificate(&header, &[])
                .expect("reference canonical-order certificate"),
        );

        let full = derive_canonical_collapse_object(&header, &[]).expect("full collapse");
        let mut header_surface = full.clone();
        header_surface.ordering.bulletin_retrievability_profile_hash = [0u8; 32];
        header_surface.ordering.bulletin_shard_manifest_hash = [0u8; 32];
        header_surface.ordering.bulletin_custody_receipt_hash = [0u8; 32];
        header_surface.sealing = Some(super::CanonicalSealingCollapse {
            height: header_surface.height,
            ..Default::default()
        });
        bind_canonical_collapse_continuity(&mut header_surface, None)
            .expect("rebind header-surface continuity");

        assert!(
            canonical_collapse_eq_on_header_surface(&full, &header_surface),
            "header-surface comparison should tolerate late materialization fields"
        );

        let mut mismatched = header_surface.clone();
        mismatched.ordering.canonical_order_certificate_hash[0] ^= 0xFF;
        bind_canonical_collapse_continuity(&mut mismatched, None)
            .expect("rebind mismatched continuity");

        assert!(
            !canonical_collapse_eq_on_header_surface(&full, &mismatched),
            "header-surface comparison should still reject fields the header really binds"
        );
    }

    #[test]
    fn canonical_collapse_commitment_stays_stable_across_materialized_ordering_bundle_fields() {
        let mut header = BlockHeader {
            height: 3,
            view: 1,
            parent_hash: [0x11u8; 32],
            parent_state_root: StateRoot(vec![0x12u8; 32]),
            state_root: StateRoot(vec![0x13u8; 32]),
            transactions_root: vec![0x14u8; 32],
            timestamp: 1_750_000_456,
            timestamp_ms: 1_750_000_456_000,
            gas_used: 9,
            validator_set: vec![vec![0x15u8; 32]],
            producer_account_id: AccountId([0x16u8; 32]),
            producer_key_suite: SignatureSuite::ED25519,
            producer_pubkey_hash: [0x17u8; 32],
            producer_pubkey: vec![0x18u8; 32],
            oracle_counter: 1,
            oracle_trace_hash: [0x19u8; 32],
            guardian_certificate: None,
            sealed_finality_proof: None,
            canonical_order_certificate: None,
            timeout_certificate: None,
            parent_qc: QuorumCertificate::default(),
            previous_canonical_collapse_commitment_hash: [0u8; 32],
            canonical_collapse_extension_certificate: None,
            publication_frontier: None,
            signature: vec![0x1Au8; 64],
        };
        header.canonical_order_certificate = Some(
            build_reference_canonical_order_certificate(&header, &[])
                .expect("reference canonical-order certificate"),
        );

        let full = derive_canonical_collapse_object(&header, &[]).expect("full collapse");
        let mut header_surface = full.clone();
        header_surface.ordering.bulletin_retrievability_profile_hash = [0u8; 32];
        header_surface.ordering.bulletin_shard_manifest_hash = [0u8; 32];
        header_surface.ordering.bulletin_custody_receipt_hash = [0u8; 32];
        header_surface.ordering.bulletin_close_hash[0] ^= 0xFF;
        header_surface.sealing = Some(super::CanonicalSealingCollapse {
            height: header_surface.height,
            ..Default::default()
        });
        bind_canonical_collapse_continuity(&mut header_surface, None)
            .expect("rebind header-surface continuity");

        assert_eq!(
            canonical_collapse_payload_hash(&full).expect("full payload hash"),
            canonical_collapse_payload_hash(&header_surface).expect("header payload hash"),
            "continuity payload should ignore late materialization fields",
        );
        assert_eq!(
            canonical_collapse_commitment_hash_from_object(&full).expect("full commitment hash"),
            canonical_collapse_commitment_hash_from_object(&header_surface)
                .expect("header commitment hash"),
            "successor predecessor commitments should stay stable across same-slot enrichment",
        );
    }

    #[test]
    fn canonical_bulletin_close_retrievability_anchor_requires_all_hashes_or_none() {
        let (_, ordered_transactions, certificate) =
            sample_committed_surface_ordering_fixture(12, 2, 14);
        let mut close = build_canonical_bulletin_close(
            &certificate.bulletin_commitment,
            &certificate.bulletin_availability_certificate,
        )
        .expect("build bulletin close");

        assert!(
            canonical_bulletin_close_retrievability_anchor(&close)
                .expect("read empty anchor")
                .is_none()
        );
        assert!(
            set_canonical_bulletin_close_retrievability_anchor(
                &mut close,
                [1u8; 32],
                [0u8; 32],
                [2u8; 32],
            )
            .is_err()
        );

        let entries = build_bulletin_surface_entries(close.height, &ordered_transactions)
            .expect("build bulletin entries");
        let profile = super::build_bulletin_retrievability_profile(
            &certificate.bulletin_commitment,
            &certificate.bulletin_availability_certificate,
        )
        .expect("build retrievability profile");
        let manifest = super::build_bulletin_shard_manifest(
            &certificate.bulletin_commitment,
            &certificate.bulletin_availability_certificate,
            &profile,
            &entries,
        )
        .expect("build shard manifest");
        let receipt =
            super::build_bulletin_custody_receipt(&profile, &manifest).expect("build receipt");
        let profile_hash =
            super::canonical_bulletin_retrievability_profile_hash(&profile).expect("profile hash");
        let manifest_hash =
            super::canonical_bulletin_shard_manifest_hash(&manifest).expect("manifest hash");
        let receipt_hash =
            super::canonical_bulletin_custody_receipt_hash(&receipt).expect("receipt hash");
        set_canonical_bulletin_close_retrievability_anchor(
            &mut close,
            profile_hash,
            manifest_hash,
            receipt_hash,
        )
        .expect("attach anchor");
        assert_eq!(
            canonical_bulletin_close_retrievability_anchor(&close)
                .expect("read anchored close"),
            Some((profile_hash, manifest_hash, receipt_hash))
        );
    }

    #[test]
    fn bulletin_retrievability_challenge_validates_missing_entries_and_rejects_false_claims() {
        let (_, ordered_transactions, certificate) =
            sample_committed_surface_ordering_fixture(13, 3, 19);
        let entries = build_bulletin_surface_entries(certificate.height, &ordered_transactions)
            .expect("build bulletin entries");
        let (profile, manifest, validator_set, assignment, receipt, response) =
            sample_bulletin_custody_plane(&certificate, &entries);
        let challenge = BulletinRetrievabilityChallenge {
            height: certificate.height,
            kind: BulletinRetrievabilityChallengeKind::MissingSurfaceEntries,
            bulletin_commitment_hash: canonical_bulletin_commitment_hash(
                &certificate.bulletin_commitment,
            )
            .expect("commitment hash"),
            bulletin_availability_certificate_hash: canonical_bulletin_availability_certificate_hash(
                &certificate.bulletin_availability_certificate,
            )
            .expect("availability hash"),
            bulletin_retrievability_profile_hash:
                canonical_bulletin_retrievability_profile_hash(&profile)
                    .expect("profile hash"),
            bulletin_shard_manifest_hash: canonical_bulletin_shard_manifest_hash(&manifest)
                .expect("manifest hash"),
            bulletin_custody_assignment_hash:
                canonical_bulletin_custody_assignment_hash(&assignment)
                    .expect("assignment hash"),
            bulletin_custody_receipt_hash: canonical_bulletin_custody_receipt_hash(&receipt)
                .expect("receipt hash"),
            bulletin_custody_response_hash: canonical_bulletin_custody_response_hash(&response)
                .expect("response hash"),
            details: "no bulletin entries remained protocol-visible for the closed slot".into(),
        };

        validate_bulletin_retrievability_challenge(
            &challenge,
            &certificate.bulletin_commitment,
            &certificate.bulletin_availability_certificate,
            Some(&profile),
            Some(&manifest),
            Some(&validator_set),
            Some(&assignment),
            Some(&receipt),
            Some(&response),
            &[],
        )
        .expect("missing entries challenge should validate");
        assert_ne!(
            canonical_bulletin_retrievability_challenge_hash(&challenge)
                .expect("challenge hash"),
            [0u8; 32]
        );

        assert!(
            validate_bulletin_retrievability_challenge(
                &challenge,
                &certificate.bulletin_commitment,
                &certificate.bulletin_availability_certificate,
                Some(&profile),
                Some(&manifest),
                Some(&validator_set),
                Some(&assignment),
                Some(&receipt),
                Some(&response),
                &entries,
            )
            .is_err()
        );
    }

    #[test]
    fn bulletin_retrievability_challenge_validates_missing_profile_manifest_and_receipt() {
        let (_, ordered_transactions, certificate) =
            sample_committed_surface_ordering_fixture(13, 3, 23);
        let entries = build_bulletin_surface_entries(certificate.height, &ordered_transactions)
            .expect("build bulletin entries");
        let profile = super::build_bulletin_retrievability_profile(
            &certificate.bulletin_commitment,
            &certificate.bulletin_availability_certificate,
        )
        .expect("build retrievability profile");
        let manifest = super::build_bulletin_shard_manifest(
            &certificate.bulletin_commitment,
            &certificate.bulletin_availability_certificate,
            &profile,
            &entries,
        )
        .expect("build shard manifest");
        let validator_set = sample_validator_set_for_retrievability_tests();
        let assignment =
            build_bulletin_custody_assignment(&profile, &manifest, &validator_set)
                .expect("build assignment");
        let receipt =
            super::build_bulletin_custody_receipt(&profile, &manifest).expect("build receipt");
        let response = build_bulletin_custody_response(
            &certificate.bulletin_commitment,
            &profile,
            &manifest,
            &assignment,
            &receipt,
            &entries,
        )
        .expect("build response");

        let missing_profile = BulletinRetrievabilityChallenge {
            height: certificate.height,
            kind: BulletinRetrievabilityChallengeKind::MissingRetrievabilityProfile,
            bulletin_commitment_hash: canonical_bulletin_commitment_hash(
                &certificate.bulletin_commitment,
            )
            .expect("commitment hash"),
            bulletin_availability_certificate_hash: canonical_bulletin_availability_certificate_hash(
                &certificate.bulletin_availability_certificate,
            )
            .expect("availability hash"),
            bulletin_retrievability_profile_hash: [0u8; 32],
            bulletin_shard_manifest_hash: [0u8; 32],
            bulletin_custody_assignment_hash: [0u8; 32],
            bulletin_custody_receipt_hash: [0u8; 32],
            bulletin_custody_response_hash: [0u8; 32],
            details: "closed slot is missing its endogenous retrievability profile".into(),
        };
        validate_bulletin_retrievability_challenge(
            &missing_profile,
            &certificate.bulletin_commitment,
            &certificate.bulletin_availability_certificate,
            None,
            None,
            None,
            None,
            None,
            None,
            &entries,
        )
        .expect("missing profile challenge should validate");
        assert!(
            validate_bulletin_retrievability_challenge(
                &missing_profile,
                &certificate.bulletin_commitment,
                &certificate.bulletin_availability_certificate,
                Some(&profile),
                None,
                None,
                None,
                None,
                None,
                &entries,
            )
            .is_err()
        );

        let missing_manifest = BulletinRetrievabilityChallenge {
            height: certificate.height,
            kind: BulletinRetrievabilityChallengeKind::MissingShardManifest,
            bulletin_commitment_hash: canonical_bulletin_commitment_hash(
                &certificate.bulletin_commitment,
            )
            .expect("commitment hash"),
            bulletin_availability_certificate_hash: canonical_bulletin_availability_certificate_hash(
                &certificate.bulletin_availability_certificate,
            )
            .expect("availability hash"),
            bulletin_retrievability_profile_hash:
                canonical_bulletin_retrievability_profile_hash(&profile)
                    .expect("profile hash"),
            bulletin_shard_manifest_hash: [0u8; 32],
            bulletin_custody_assignment_hash: [0u8; 32],
            bulletin_custody_receipt_hash: [0u8; 32],
            bulletin_custody_response_hash: [0u8; 32],
            details: "closed slot is missing its deterministic shard manifest".into(),
        };
        validate_bulletin_retrievability_challenge(
            &missing_manifest,
            &certificate.bulletin_commitment,
            &certificate.bulletin_availability_certificate,
            Some(&profile),
            None,
            None,
            None,
            None,
            None,
            &entries,
        )
        .expect("missing manifest challenge should validate");
        assert!(
            validate_bulletin_retrievability_challenge(
                &missing_manifest,
                &certificate.bulletin_commitment,
                &certificate.bulletin_availability_certificate,
                Some(&profile),
                Some(&manifest),
                None,
                None,
                None,
                None,
                &entries,
            )
            .is_err()
        );

        let missing_receipt = BulletinRetrievabilityChallenge {
            height: certificate.height,
            kind: BulletinRetrievabilityChallengeKind::MissingCustodyReceipt,
            bulletin_commitment_hash: canonical_bulletin_commitment_hash(
                &certificate.bulletin_commitment,
            )
            .expect("commitment hash"),
            bulletin_availability_certificate_hash: canonical_bulletin_availability_certificate_hash(
                &certificate.bulletin_availability_certificate,
            )
            .expect("availability hash"),
            bulletin_retrievability_profile_hash:
                canonical_bulletin_retrievability_profile_hash(&profile)
                    .expect("profile hash"),
            bulletin_shard_manifest_hash: canonical_bulletin_shard_manifest_hash(&manifest)
                .expect("manifest hash"),
            bulletin_custody_assignment_hash:
                canonical_bulletin_custody_assignment_hash(&assignment)
                    .expect("assignment hash"),
            bulletin_custody_receipt_hash: [0u8; 32],
            bulletin_custody_response_hash: [0u8; 32],
            details: "closed slot is missing its deterministic custody receipt".into(),
        };
        validate_bulletin_retrievability_challenge(
            &missing_receipt,
            &certificate.bulletin_commitment,
            &certificate.bulletin_availability_certificate,
            Some(&profile),
            Some(&manifest),
            Some(&validator_set),
            Some(&assignment),
            None,
            None,
            &entries,
        )
        .expect("missing receipt challenge should validate");
        assert!(
            validate_bulletin_retrievability_challenge(
                &missing_receipt,
                &certificate.bulletin_commitment,
                &certificate.bulletin_availability_certificate,
                Some(&profile),
                Some(&manifest),
                Some(&validator_set),
                Some(&assignment),
                Some(&receipt),
                Some(&response),
                &entries,
            )
            .is_err()
        );
    }

    #[test]
    fn bulletin_retrievability_challenge_validates_contradictory_manifest() {
        let (_, ordered_transactions, certificate) =
            sample_committed_surface_ordering_fixture(13, 3, 29);
        let entries = build_bulletin_surface_entries(certificate.height, &ordered_transactions)
            .expect("build bulletin entries");
        let profile = super::build_bulletin_retrievability_profile(
            &certificate.bulletin_commitment,
            &certificate.bulletin_availability_certificate,
        )
        .expect("build retrievability profile");
        let mut manifest = super::build_bulletin_shard_manifest(
            &certificate.bulletin_commitment,
            &certificate.bulletin_availability_certificate,
            &profile,
            &entries,
        )
        .expect("build shard manifest");
        manifest.shard_commitment_root[0] ^= 0x5a;
        let validator_set = sample_validator_set_for_retrievability_tests();
        let challenge = BulletinRetrievabilityChallenge {
            height: certificate.height,
            kind: BulletinRetrievabilityChallengeKind::ContradictoryShardManifest,
            bulletin_commitment_hash: canonical_bulletin_commitment_hash(
                &certificate.bulletin_commitment,
            )
            .expect("commitment hash"),
            bulletin_availability_certificate_hash: canonical_bulletin_availability_certificate_hash(
                &certificate.bulletin_availability_certificate,
            )
            .expect("availability hash"),
            bulletin_retrievability_profile_hash:
                canonical_bulletin_retrievability_profile_hash(&profile)
                    .expect("profile hash"),
            bulletin_shard_manifest_hash: super::canonical_bulletin_shard_manifest_hash(&manifest)
                .expect("manifest hash"),
            bulletin_custody_assignment_hash: [0u8; 32],
            bulletin_custody_receipt_hash: [0u8; 32],
            bulletin_custody_response_hash: [0u8; 32],
            details: "published shard manifest contradicts the deterministic slot geometry".into(),
        };

        validate_bulletin_retrievability_challenge(
            &challenge,
            &certificate.bulletin_commitment,
            &certificate.bulletin_availability_certificate,
            Some(&profile),
            Some(&manifest),
            None,
            None,
            None,
            None,
            &entries,
        )
        .expect("contradictory manifest challenge should validate");

        let valid_manifest = super::build_bulletin_shard_manifest(
            &certificate.bulletin_commitment,
            &certificate.bulletin_availability_certificate,
            &profile,
            &entries,
        )
        .expect("build valid manifest");
        assert!(
            validate_bulletin_retrievability_challenge(
                &challenge,
                &certificate.bulletin_commitment,
                &certificate.bulletin_availability_certificate,
                Some(&profile),
                Some(&valid_manifest),
                Some(&validator_set),
                None,
                None,
                None,
                &entries,
            )
            .is_err()
        );
    }

    #[test]
    fn bulletin_retrievability_challenge_validates_contradictory_custody_receipt() {
        let (_, ordered_transactions, certificate) =
            sample_committed_surface_ordering_fixture(13, 3, 31);
        let entries = build_bulletin_surface_entries(certificate.height, &ordered_transactions)
            .expect("build bulletin entries");
        let profile = super::build_bulletin_retrievability_profile(
            &certificate.bulletin_commitment,
            &certificate.bulletin_availability_certificate,
        )
        .expect("build retrievability profile");
        let manifest = super::build_bulletin_shard_manifest(
            &certificate.bulletin_commitment,
            &certificate.bulletin_availability_certificate,
            &profile,
            &entries,
        )
        .expect("build shard manifest");
        let validator_set = sample_validator_set_for_retrievability_tests();
        let assignment =
            build_bulletin_custody_assignment(&profile, &manifest, &validator_set)
                .expect("build assignment");
        let mut receipt =
            super::build_bulletin_custody_receipt(&profile, &manifest).expect("build receipt");
        receipt.custody_root[0] ^= 0x33;
        let challenge = BulletinRetrievabilityChallenge {
            height: certificate.height,
            kind: BulletinRetrievabilityChallengeKind::ContradictoryCustodyReceipt,
            bulletin_commitment_hash: canonical_bulletin_commitment_hash(
                &certificate.bulletin_commitment,
            )
            .expect("commitment hash"),
            bulletin_availability_certificate_hash: canonical_bulletin_availability_certificate_hash(
                &certificate.bulletin_availability_certificate,
            )
            .expect("availability hash"),
            bulletin_retrievability_profile_hash:
                canonical_bulletin_retrievability_profile_hash(&profile)
                    .expect("profile hash"),
            bulletin_shard_manifest_hash: super::canonical_bulletin_shard_manifest_hash(&manifest)
                .expect("manifest hash"),
            bulletin_custody_assignment_hash:
                canonical_bulletin_custody_assignment_hash(&assignment)
                    .expect("assignment hash"),
            bulletin_custody_receipt_hash:
                canonical_bulletin_custody_receipt_hash(&receipt).expect("receipt hash"),
            bulletin_custody_response_hash: [0u8; 32],
            details: "published custody receipt contradicts the deterministic manifest binding"
                .into(),
        };

        validate_bulletin_retrievability_challenge(
            &challenge,
            &certificate.bulletin_commitment,
            &certificate.bulletin_availability_certificate,
            Some(&profile),
            Some(&manifest),
            Some(&validator_set),
            Some(&assignment),
            Some(&receipt),
            None,
            &entries,
        )
        .expect("contradictory custody receipt challenge should validate");

        let valid_receipt =
            super::build_bulletin_custody_receipt(&profile, &manifest).expect("build receipt");
        assert!(
            validate_bulletin_retrievability_challenge(
                &challenge,
                &certificate.bulletin_commitment,
                &certificate.bulletin_availability_certificate,
                Some(&profile),
                Some(&manifest),
                Some(&validator_set),
                Some(&assignment),
                Some(&valid_receipt),
                None,
                &entries,
            )
            .is_err()
        );
    }

    #[test]
    fn bulletin_retrievability_challenge_validates_invalid_surface_entries() {
        let (_, ordered_transactions, certificate) =
            sample_committed_surface_ordering_fixture(13, 3, 37);
        let entries = build_bulletin_surface_entries(certificate.height, &ordered_transactions)
            .expect("build bulletin entries");
        let (profile, manifest, validator_set, assignment, receipt, response) =
            sample_bulletin_custody_plane(&certificate, &entries);
        let mut invalid_entries = entries.clone();
        invalid_entries[0].tx_hash[0] ^= 0x55;
        let challenge = BulletinRetrievabilityChallenge {
            height: certificate.height,
            kind: BulletinRetrievabilityChallengeKind::InvalidSurfaceEntries,
            bulletin_commitment_hash: canonical_bulletin_commitment_hash(
                &certificate.bulletin_commitment,
            )
            .expect("commitment hash"),
            bulletin_availability_certificate_hash: canonical_bulletin_availability_certificate_hash(
                &certificate.bulletin_availability_certificate,
            )
            .expect("availability hash"),
            bulletin_retrievability_profile_hash:
                canonical_bulletin_retrievability_profile_hash(&profile)
                    .expect("profile hash"),
            bulletin_shard_manifest_hash: canonical_bulletin_shard_manifest_hash(&manifest)
                .expect("manifest hash"),
            bulletin_custody_assignment_hash:
                canonical_bulletin_custody_assignment_hash(&assignment)
                    .expect("assignment hash"),
            bulletin_custody_receipt_hash: canonical_bulletin_custody_receipt_hash(&receipt)
                .expect("receipt hash"),
            bulletin_custody_response_hash: canonical_bulletin_custody_response_hash(&response)
                .expect("response hash"),
            details:
                "published bulletin entries do not reconstruct the canonical bulletin surface"
                    .into(),
        };

        validate_bulletin_retrievability_challenge(
            &challenge,
            &certificate.bulletin_commitment,
            &certificate.bulletin_availability_certificate,
            Some(&profile),
            Some(&manifest),
            Some(&validator_set),
            Some(&assignment),
            Some(&receipt),
            Some(&response),
            &invalid_entries,
        )
        .expect("invalid surface entries challenge should validate");

        assert!(
            validate_bulletin_retrievability_challenge(
                &challenge,
                &certificate.bulletin_commitment,
                &certificate.bulletin_availability_certificate,
                Some(&profile),
                Some(&manifest),
                Some(&validator_set),
                Some(&assignment),
                Some(&receipt),
                Some(&response),
                &entries,
            )
            .is_err()
        );
    }

    #[test]
    fn endogenous_bulletin_extraction_requires_bound_retrievability_objects() {
        let (_, ordered_transactions, certificate) =
            sample_committed_surface_ordering_fixture(14, 4, 23);
        let entries = build_bulletin_surface_entries(certificate.height, &ordered_transactions)
            .expect("build bulletin entries");
        let (profile, manifest, validator_set, assignment, receipt, response) =
            sample_bulletin_custody_plane(&certificate, &entries);
        let mut close = build_canonical_bulletin_close(
            &certificate.bulletin_commitment,
            &certificate.bulletin_availability_certificate,
        )
        .expect("build close");
        let profile_hash =
            canonical_bulletin_retrievability_profile_hash(&profile).expect("profile hash");
        let manifest_hash =
            canonical_bulletin_shard_manifest_hash(&manifest).expect("manifest hash");
        let receipt_hash =
            canonical_bulletin_custody_receipt_hash(&receipt).expect("receipt hash");
        set_canonical_bulletin_close_retrievability_anchor(
            &mut close,
            profile_hash,
            manifest_hash,
            receipt_hash,
        )
        .expect("attach retrievability anchor");

        assert_eq!(
            extract_endogenous_canonical_bulletin_surface(
                &close,
                &certificate.bulletin_commitment,
                &certificate.bulletin_availability_certificate,
                &profile,
                &manifest,
                &assignment,
                &receipt,
                &response,
                &entries,
                &validator_set,
            )
            .expect("endogenous extraction"),
            entries
        );

        let mut wrong_close = close.clone();
        wrong_close.bulletin_custody_receipt_hash[0] ^= 0xFF;
        assert!(
            extract_endogenous_canonical_bulletin_surface(
                &wrong_close,
                &certificate.bulletin_commitment,
                &certificate.bulletin_availability_certificate,
                &profile,
                &manifest,
                &assignment,
                &receipt,
                &response,
                &entries,
                &validator_set,
            )
            .is_err()
        );
    }

    #[test]
    fn derive_canonical_order_execution_object_returns_abort_without_certificate() {
        let header = BlockHeader {
            height: 13,
            view: 1,
            parent_hash: [31u8; 32],
            parent_state_root: StateRoot(vec![1u8; 32]),
            state_root: StateRoot(vec![2u8; 32]),
            transactions_root: vec![3u8; 32],
            timestamp: 1_750_000_888,
            timestamp_ms: 1_750_000_888_000,
            gas_used: 0,
            validator_set: Vec::new(),
            producer_account_id: AccountId([14u8; 32]),
            producer_key_suite: SignatureSuite::ED25519,
            producer_pubkey_hash: [15u8; 32],
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

        let abort = derive_canonical_order_execution_object(&header, &[])
            .expect_err("missing canonical-order certificate must derive abort");
        assert_eq!(abort.height, header.height);
        assert_eq!(
            abort.reason,
            CanonicalOrderAbortReason::MissingOrderCertificate
        );
        assert_eq!(abort.canonical_order_certificate_hash, [0u8; 32]);
        assert!(abort
            .details
            .contains("does not carry a canonical-order certificate"));
    }

    #[test]
    fn derive_canonical_order_public_obstruction_reports_invalid_surface() {
        let (header, ordered_transactions, _certificate) =
            sample_committed_surface_ordering_fixture(19, 2, 16);
        let invalid_surface = vec![ordered_transactions[0].clone()];

        let abort = derive_canonical_order_public_obstruction(&header, &invalid_surface)
            .expect("invalid surface should derive obstruction");
        assert_eq!(abort.height, header.height);
        assert_eq!(
            abort.reason,
            CanonicalOrderAbortReason::BulletinSurfaceMismatch
        );
        assert_ne!(abort.canonical_order_certificate_hash, [0u8; 32]);
        assert!(abort
            .details
            .contains("proof-carried bulletin surface is invalid"));
    }

    #[test]
    fn derive_canonical_order_public_obstruction_reports_surface_reconstruction_failure() {
        let (header, ordered_transactions, _) =
            sample_committed_surface_ordering_fixture(29, 3, 24);
        let duplicate_transactions = vec![
            ordered_transactions[0].clone(),
            ordered_transactions[0].clone(),
        ];
        let abort = derive_canonical_order_public_obstruction(&header, &duplicate_transactions)
            .expect("duplicate tx surface should derive obstruction");
        assert_eq!(
            abort.reason,
            CanonicalOrderAbortReason::BulletinSurfaceReconstructionFailure
        );
        assert!(abort
            .details
            .contains("failed to reconstruct canonical bulletin surface"));
    }

    #[test]
    fn derive_canonical_order_public_obstruction_reports_invalid_bulletin_close() {
        let (mut header, ordered_transactions, mut certificate) =
            sample_committed_surface_ordering_fixture(31, 4, 30);
        certificate.bulletin_availability_certificate.height += 1;
        header.canonical_order_certificate = Some(certificate);
        let abort = derive_canonical_order_public_obstruction(&header, &ordered_transactions)
            .expect("invalid bulletin close should derive obstruction");
        assert_eq!(
            abort.reason,
            CanonicalOrderAbortReason::InvalidBulletinClose
        );
    }

    #[test]
    fn derive_canonical_order_public_obstruction_reports_omission_dominance() {
        let (mut header, ordered_transactions, mut certificate) =
            sample_committed_surface_ordering_fixture(33, 5, 35);
        let tx_hash = ordered_transactions[0].hash().expect("tx hash");
        certificate.omission_proofs.push(OmissionProof {
            height: header.height,
            offender_account_id: AccountId([99u8; 32]),
            tx_hash,
            bulletin_root: certificate.bulletin_commitment.bulletin_root,
            details: "objective omission".into(),
        });
        header.canonical_order_certificate = Some(certificate);
        let abort = derive_canonical_order_public_obstruction(&header, &ordered_transactions)
            .expect("omissions should derive obstruction");
        assert_eq!(abort.reason, CanonicalOrderAbortReason::OmissionDominated);
    }

    #[test]
    fn derive_canonical_order_public_obstruction_reports_certificate_height_mismatch() {
        let (mut header, ordered_transactions, mut certificate) =
            sample_committed_surface_ordering_fixture(35, 6, 40);
        certificate.height += 1;
        header.canonical_order_certificate = Some(certificate);
        let abort = derive_canonical_order_public_obstruction(&header, &ordered_transactions)
            .expect("height mismatch should derive obstruction");
        assert_eq!(
            abort.reason,
            CanonicalOrderAbortReason::CertificateHeightMismatch
        );
    }

    #[test]
    fn derive_canonical_order_public_obstruction_reports_randomness_mismatch() {
        let (mut header, ordered_transactions, mut certificate) =
            sample_committed_surface_ordering_fixture(37, 7, 45);
        certificate.randomness_beacon[0] ^= 0xFF;
        header.canonical_order_certificate = Some(certificate);
        let abort = derive_canonical_order_public_obstruction(&header, &ordered_transactions)
            .expect("randomness mismatch should derive obstruction");
        assert_eq!(abort.reason, CanonicalOrderAbortReason::RandomnessMismatch);
    }

    #[test]
    fn derive_canonical_order_public_obstruction_reports_transactions_root_mismatch() {
        let (mut header, ordered_transactions, mut certificate) =
            sample_committed_surface_ordering_fixture(39, 8, 50);
        certificate.ordered_transactions_root_hash[0] ^= 0xFF;
        header.canonical_order_certificate = Some(certificate);
        let abort = derive_canonical_order_public_obstruction(&header, &ordered_transactions)
            .expect("ordered transactions root mismatch should derive obstruction");
        assert_eq!(
            abort.reason,
            CanonicalOrderAbortReason::OrderedTransactionsRootMismatch
        );
    }

    #[test]
    fn derive_canonical_order_public_obstruction_reports_state_root_mismatch() {
        let (mut header, ordered_transactions, mut certificate) =
            sample_committed_surface_ordering_fixture(41, 9, 55);
        certificate.resulting_state_root_hash[0] ^= 0xFF;
        header.canonical_order_certificate = Some(certificate);
        let abort = derive_canonical_order_public_obstruction(&header, &ordered_transactions)
            .expect("resulting state root mismatch should derive obstruction");
        assert_eq!(
            abort.reason,
            CanonicalOrderAbortReason::ResultingStateRootMismatch
        );
    }

    #[test]
    fn derive_canonical_order_public_obstruction_reports_invalid_public_inputs_hash() {
        let (mut header, ordered_transactions, mut certificate) =
            sample_committed_surface_ordering_fixture(43, 10, 60);
        certificate.proof.public_inputs_hash[0] ^= 0xFF;
        header.canonical_order_certificate = Some(certificate);
        let abort = derive_canonical_order_public_obstruction(&header, &ordered_transactions)
            .expect("public-input mismatch should derive obstruction");
        assert_eq!(
            abort.reason,
            CanonicalOrderAbortReason::InvalidPublicInputsHash
        );
    }

    #[test]
    fn derive_canonical_order_public_obstruction_reports_invalid_availability_certificate() {
        let (mut header, ordered_transactions, mut certificate) =
            sample_committed_surface_ordering_fixture(45, 11, 65);
        certificate
            .bulletin_availability_certificate
            .recoverability_root[0] ^= 0xFF;
        header.canonical_order_certificate = Some(certificate);
        let abort = derive_canonical_order_public_obstruction(&header, &ordered_transactions)
            .expect("invalid availability certificate should derive obstruction");
        assert_eq!(
            abort.reason,
            CanonicalOrderAbortReason::InvalidBulletinAvailabilityCertificate
        );
    }

    #[test]
    fn derive_canonical_order_public_obstruction_reports_invalid_proof_binding() {
        let (mut header, ordered_transactions, mut certificate) =
            sample_committed_surface_ordering_fixture(47, 12, 70);
        certificate.proof.proof_bytes[0] ^= 0xFF;
        header.canonical_order_certificate = Some(certificate);
        let abort = derive_canonical_order_public_obstruction(&header, &ordered_transactions)
            .expect("invalid proof binding should derive obstruction");
        assert_eq!(abort.reason, CanonicalOrderAbortReason::InvalidProofBinding);
    }

    #[test]
    fn publication_frontier_verifies_against_header_and_predecessor() {
        let (previous_header, _, _) = sample_committed_surface_ordering_fixture(1, 1, 71);
        let previous_frontier =
            build_publication_frontier(&previous_header, None).expect("previous frontier");
        verify_publication_frontier(&previous_header, &previous_frontier, None)
            .expect("genesis frontier should verify");

        let (header, _, _) = sample_committed_surface_ordering_fixture(2, 2, 72);
        let frontier =
            build_publication_frontier(&header, Some(&previous_frontier)).expect("frontier");
        verify_publication_frontier(&header, &frontier, Some(&previous_frontier))
            .expect("frontier should verify against predecessor");
    }

    #[test]
    fn publication_frontier_conflict_contradiction_verifies() {
        let (previous_header, _, _) = sample_committed_surface_ordering_fixture(1, 1, 73);
        let previous_frontier =
            build_publication_frontier(&previous_header, None).expect("previous frontier");
        let (header, _, _) = sample_committed_surface_ordering_fixture(2, 2, 74);
        let reference_frontier =
            build_publication_frontier(&header, Some(&previous_frontier)).expect("reference");
        let mut candidate_frontier = reference_frontier.clone();
        candidate_frontier.view += 1;
        candidate_frontier.bulletin_commitment_hash[0] ^= 0xFF;

        verify_publication_frontier_contradiction(&PublicationFrontierContradiction {
            height: header.height,
            kind: PublicationFrontierContradictionKind::ConflictingFrontier,
            candidate_frontier,
            reference_frontier,
        })
        .expect("conflicting frontier contradiction should verify");
    }

    #[test]
    fn publication_frontier_stale_parent_link_contradiction_verifies() {
        let (previous_header, _, _) = sample_committed_surface_ordering_fixture(4, 1, 75);
        let previous_frontier =
            build_publication_frontier(&previous_header, None).expect("previous frontier");
        let (header, _, _) = sample_committed_surface_ordering_fixture(5, 2, 76);
        let mut candidate_frontier =
            build_publication_frontier(&header, Some(&previous_frontier)).expect("frontier");
        candidate_frontier.parent_frontier_hash[0] ^= 0xAA;

        verify_publication_frontier_contradiction(&PublicationFrontierContradiction {
            height: header.height,
            kind: PublicationFrontierContradictionKind::StaleParentLink,
            candidate_frontier,
            reference_frontier: previous_frontier,
        })
        .expect("stale frontier contradiction should verify");
    }

    #[test]
    fn recovery_capsule_hash_changes_with_payload_commitment() {
        let mut capsule = RecoveryCapsule {
            height: 9,
            coding: RecoveryCodingDescriptor::deterministic_scaffold(),
            recovery_committee_root_hash: [1u8; 32],
            payload_commitment_hash: [2u8; 32],
            coding_root_hash: [3u8; 32],
            recovery_window_close_ms: 1_750_000_999_000,
        };
        let original = canonical_recovery_capsule_hash(&capsule).expect("capsule hash");
        capsule.payload_commitment_hash[0] ^= 0xFF;
        let updated = canonical_recovery_capsule_hash(&capsule).expect("updated capsule hash");
        assert_ne!(original, updated);
    }

    #[test]
    fn recovery_witness_and_missing_share_hashes_bind_distinct_evidence() {
        let certificate = RecoveryWitnessCertificate {
            height: 10,
            epoch: 4,
            witness_manifest_hash: [5u8; 32],
            recovery_capsule_hash: [6u8; 32],
            share_commitment_hash: [7u8; 32],
        };
        let receipt = RecoveryShareReceipt {
            height: 10,
            witness_manifest_hash: certificate.witness_manifest_hash,
            block_commitment_hash: [8u8; 32],
            share_commitment_hash: certificate.share_commitment_hash,
        };
        let material = RecoveryShareMaterial {
            height: 10,
            witness_manifest_hash: certificate.witness_manifest_hash,
            block_commitment_hash: receipt.block_commitment_hash,
            coding: transparent_recovery_coding(3, 2),
            share_index: 0,
            share_commitment_hash: certificate.share_commitment_hash,
            material_bytes: vec![1, 2, 3, 4],
        };
        let envelope = AssignedRecoveryShareEnvelopeV1 {
            recovery_capsule_hash: certificate.recovery_capsule_hash,
            expected_share_commitment_hash: certificate.share_commitment_hash,
            share_material: material.clone(),
        };
        let mut missing = MissingRecoveryShare {
            height: 10,
            witness_manifest_hash: certificate.witness_manifest_hash,
            recovery_capsule_hash: certificate.recovery_capsule_hash,
            recovery_window_close_ms: 1_750_001_111_000,
        };

        let certificate_hash = canonical_recovery_witness_certificate_hash(&certificate)
            .expect("recovery witness certificate hash");
        let receipt_hash =
            canonical_recovery_share_receipt_hash(&receipt).expect("recovery share receipt hash");
        let material_hash = canonical_recovery_share_material_hash(&material)
            .expect("recovery share material hash");
        let envelope_hash = canonical_assigned_recovery_share_envelope_hash(&envelope)
            .expect("assigned recovery share envelope hash");
        let missing_hash =
            canonical_missing_recovery_share_hash(&missing).expect("missing share hash");
        assert_ne!(certificate_hash, receipt_hash);
        assert_ne!(certificate_hash, material_hash);
        assert_ne!(certificate_hash, envelope_hash);
        assert_ne!(certificate_hash, missing_hash);
        assert_ne!(receipt_hash, material_hash);
        assert_ne!(receipt_hash, envelope_hash);
        assert_ne!(receipt_hash, missing_hash);
        assert_ne!(material_hash, envelope_hash);
        assert_ne!(material_hash, missing_hash);
        assert_ne!(envelope_hash, missing_hash);

        assert_eq!(material.to_recovery_share_receipt(), receipt);
        assert_eq!(
            envelope.recovery_binding(),
            GuardianWitnessRecoveryBinding {
                recovery_capsule_hash: certificate.recovery_capsule_hash,
                share_commitment_hash: certificate.share_commitment_hash,
            }
        );
        envelope
            .validate_for_witness(certificate.witness_manifest_hash, certificate.height)
            .expect("assigned recovery share envelope should validate");

        missing.recovery_window_close_ms += 1_000;
        let updated_missing_hash =
            canonical_missing_recovery_share_hash(&missing).expect("updated missing share hash");
        assert_ne!(missing_hash, updated_missing_hash);
    }

    #[test]
    fn recoverable_slot_payload_hash_changes_with_transaction_hashes() {
        let certificate = CanonicalOrderCertificate {
            height: 11,
            bulletin_commitment: BulletinCommitment {
                height: 11,
                cutoff_timestamp_ms: 1_750_002_222_000,
                bulletin_root: [31u8; 32],
                entry_count: 2,
            },
            bulletin_availability_certificate: BulletinAvailabilityCertificate {
                height: 11,
                bulletin_commitment_hash: [32u8; 32],
                recoverability_root: [33u8; 32],
            },
            randomness_beacon: [34u8; 32],
            ordered_transactions_root_hash: [35u8; 32],
            resulting_state_root_hash: [36u8; 32],
            proof: Default::default(),
            omission_proofs: Vec::new(),
        };
        let mut payload = RecoverableSlotPayloadV1 {
            height: 11,
            view: 4,
            producer_account_id: AccountId([37u8; 32]),
            block_commitment_hash: [38u8; 32],
            canonical_order_certificate: certificate,
            ordered_transaction_hashes: vec![[39u8; 32], [40u8; 32]],
        };

        let original = canonical_recoverable_slot_payload_hash(&payload).expect("payload hash");
        payload.ordered_transaction_hashes[1][0] ^= 0xFF;
        let updated =
            canonical_recoverable_slot_payload_hash(&payload).expect("updated payload hash");
        assert_ne!(original, updated);
    }

    #[test]
    fn recoverable_slot_payload_v2_hash_changes_with_transaction_bytes() {
        let certificate = CanonicalOrderCertificate {
            height: 12,
            bulletin_commitment: BulletinCommitment {
                height: 12,
                cutoff_timestamp_ms: 1_750_003_333_000,
                bulletin_root: [41u8; 32],
                entry_count: 2,
            },
            bulletin_availability_certificate: BulletinAvailabilityCertificate {
                height: 12,
                bulletin_commitment_hash: [42u8; 32],
                recoverability_root: [43u8; 32],
            },
            randomness_beacon: [44u8; 32],
            ordered_transactions_root_hash: [45u8; 32],
            resulting_state_root_hash: [46u8; 32],
            proof: Default::default(),
            omission_proofs: Vec::new(),
        };
        let mut payload = RecoverableSlotPayloadV2 {
            height: 12,
            view: 5,
            producer_account_id: AccountId([47u8; 32]),
            block_commitment_hash: [48u8; 32],
            canonical_order_certificate: certificate,
            ordered_transaction_bytes: vec![vec![49u8, 50u8], vec![51u8, 52u8]],
        };

        let original =
            canonical_recoverable_slot_payload_v2_hash(&payload).expect("payload v2 hash");
        payload.ordered_transaction_bytes[1][1] ^= 0xFF;
        let updated =
            canonical_recoverable_slot_payload_v2_hash(&payload).expect("updated payload v2 hash");
        assert_ne!(original, updated);
    }

    #[test]
    fn recoverable_slot_payload_v3_hash_changes_with_publication_bundle_bytes() {
        let certificate = CanonicalOrderCertificate {
            height: 13,
            bulletin_commitment: BulletinCommitment {
                height: 13,
                cutoff_timestamp_ms: 1_750_004_444_000,
                bulletin_root: [51u8; 32],
                entry_count: 2,
            },
            bulletin_availability_certificate: BulletinAvailabilityCertificate {
                height: 13,
                bulletin_commitment_hash: [52u8; 32],
                recoverability_root: [53u8; 32],
            },
            randomness_beacon: [54u8; 32],
            ordered_transactions_root_hash: [55u8; 32],
            resulting_state_root_hash: [56u8; 32],
            proof: Default::default(),
            omission_proofs: Vec::new(),
        };
        let mut payload = RecoverableSlotPayloadV3 {
            height: 13,
            view: 6,
            producer_account_id: AccountId([57u8; 32]),
            block_commitment_hash: [58u8; 32],
            parent_block_hash: [57u8; 32],
            canonical_order_certificate: certificate,
            ordered_transaction_bytes: vec![vec![59u8, 60u8], vec![61u8, 62u8]],
            canonical_order_publication_bundle_bytes: vec![63u8, 64u8, 65u8],
        };

        let original =
            canonical_recoverable_slot_payload_v3_hash(&payload).expect("payload v3 hash");
        payload.canonical_order_publication_bundle_bytes[2] ^= 0xFF;
        let updated =
            canonical_recoverable_slot_payload_v3_hash(&payload).expect("updated payload v3 hash");
        assert_ne!(original, updated);
    }

    #[test]
    fn recoverable_slot_payload_v4_hash_changes_with_bulletin_close_bytes() {
        let (mut payload, _, _) = build_sample_recoverable_slot_payload_v4(13, 6, 57);
        let original =
            canonical_recoverable_slot_payload_v4_hash(&payload).expect("payload v4 hash");
        payload.canonical_bulletin_close_bytes[0] ^= 0xFF;
        let updated =
            canonical_recoverable_slot_payload_v4_hash(&payload).expect("updated payload v4 hash");
        assert_ne!(original, updated);
    }

    #[test]
    fn recoverable_slot_payload_v5_hash_changes_with_bulletin_surface_entries() {
        let (mut payload, _, _, _) = build_sample_recoverable_slot_payload_v5(14, 7, 63);
        let original =
            canonical_recoverable_slot_payload_v5_hash(&payload).expect("payload v5 hash");
        payload.bulletin_surface_entries[0].tx_hash[0] ^= 0xFF;
        let updated =
            canonical_recoverable_slot_payload_v5_hash(&payload).expect("updated payload v5 hash");
        assert_ne!(original, updated);
    }

    #[test]
    fn recovered_publication_bundle_hash_changes_with_supporting_witnesses() {
        let recovered = RecoveredPublicationBundle {
            height: 14,
            block_commitment_hash: [66u8; 32],
            parent_block_commitment_hash: [65u8; 32],
            coding: xor_recovery_coding(3, 2),
            supporting_witness_manifest_hashes: vec![[67u8; 32], [68u8; 32]],
            recoverable_slot_payload_hash: [69u8; 32],
            recoverable_full_surface_hash: [70u8; 32],
            canonical_order_publication_bundle_hash: [71u8; 32],
            canonical_bulletin_close_hash: [72u8; 32],
        };
        let original =
            canonical_recovered_publication_bundle_hash(&recovered).expect("recovered hash");
        let mut updated = recovered.clone();
        updated.supporting_witness_manifest_hashes.swap(0, 1);
        let reordered =
            canonical_recovered_publication_bundle_hash(&updated).expect("reordered hash");
        assert_ne!(original, reordered);

        let normalized = normalize_recovered_publication_bundle_supporting_witnesses(
            &updated.supporting_witness_manifest_hashes,
        )
        .expect("normalize supporting witnesses");
        assert_eq!(normalized, vec![[67u8; 32], [68u8; 32]]);
    }

    #[test]
    fn archived_recovered_history_segment_builder_chains_previous_hash_deterministically() {
        let recovered_a = RecoveredPublicationBundle {
            height: 21,
            block_commitment_hash: [80u8; 32],
            parent_block_commitment_hash: [79u8; 32],
            coding: xor_recovery_coding(3, 2),
            supporting_witness_manifest_hashes: vec![[81u8; 32], [82u8; 32]],
            recoverable_slot_payload_hash: [83u8; 32],
            recoverable_full_surface_hash: [84u8; 32],
            canonical_order_publication_bundle_hash: [85u8; 32],
            canonical_bulletin_close_hash: [86u8; 32],
        };
        let recovered_b = RecoveredPublicationBundle {
            height: 22,
            block_commitment_hash: [87u8; 32],
            parent_block_commitment_hash: [80u8; 32],
            coding: xor_recovery_coding(3, 2),
            supporting_witness_manifest_hashes: vec![[88u8; 32], [89u8; 32]],
            recoverable_slot_payload_hash: [90u8; 32],
            recoverable_full_surface_hash: [91u8; 32],
            canonical_order_publication_bundle_hash: [92u8; 32],
            canonical_bulletin_close_hash: [93u8; 32],
        };

        let previous_segment = build_archived_recovered_history_segment(
            std::slice::from_ref(&recovered_a),
            None,
            None,
            &sample_archived_recovered_history_profile_for_tests(),
            &sample_archived_recovered_history_profile_activation_for_tests(),
        )
        .expect("previous segment");
        let current_segment = build_archived_recovered_history_segment(
            std::slice::from_ref(&recovered_b),
            Some(&previous_segment),
            None,
            &sample_archived_recovered_history_profile_for_tests(),
            &sample_archived_recovered_history_profile_activation_for_tests(),
        )
        .expect("current segment");

        assert_eq!(current_segment.start_height, 22);
        assert_eq!(current_segment.end_height, 22);
        assert_eq!(
            current_segment.previous_archived_segment_hash,
            canonical_archived_recovered_history_segment_hash(&previous_segment)
                .expect("previous segment hash")
        );
    }

    #[test]
    fn archived_recovered_history_segment_builder_derives_overlap_root_from_range() {
        let recovered_a = RecoveredPublicationBundle {
            height: 31,
            block_commitment_hash: [94u8; 32],
            parent_block_commitment_hash: [93u8; 32],
            coding: gf256_recovery_coding(4, 2),
            supporting_witness_manifest_hashes: vec![[95u8; 32], [96u8; 32]],
            recoverable_slot_payload_hash: [97u8; 32],
            recoverable_full_surface_hash: [98u8; 32],
            canonical_order_publication_bundle_hash: [99u8; 32],
            canonical_bulletin_close_hash: [100u8; 32],
        };
        let recovered_b = RecoveredPublicationBundle {
            height: 32,
            block_commitment_hash: [101u8; 32],
            parent_block_commitment_hash: [94u8; 32],
            coding: gf256_recovery_coding(4, 2),
            supporting_witness_manifest_hashes: vec![[102u8; 32], [103u8; 32]],
            recoverable_slot_payload_hash: [104u8; 32],
            recoverable_full_surface_hash: [105u8; 32],
            canonical_order_publication_bundle_hash: [106u8; 32],
            canonical_bulletin_close_hash: [107u8; 32],
        };
        let recovered_c = RecoveredPublicationBundle {
            height: 33,
            block_commitment_hash: [108u8; 32],
            parent_block_commitment_hash: [101u8; 32],
            coding: gf256_recovery_coding(4, 2),
            supporting_witness_manifest_hashes: vec![[109u8; 32], [110u8; 32]],
            recoverable_slot_payload_hash: [111u8; 32],
            recoverable_full_surface_hash: [112u8; 32],
            canonical_order_publication_bundle_hash: [113u8; 32],
            canonical_bulletin_close_hash: [114u8; 32],
        };
        let segment = build_archived_recovered_history_segment(
            &[
                recovered_a.clone(),
                recovered_b.clone(),
                recovered_c.clone(),
            ],
            None,
            Some((32, 33)),
            &sample_archived_recovered_history_profile_for_tests(),
            &sample_archived_recovered_history_profile_activation_for_tests(),
        )
        .expect("segment");

        let overlap_hashes = vec![
            canonical_recovered_publication_bundle_hash(&recovered_b).expect("recovered b hash"),
            canonical_recovered_publication_bundle_hash(&recovered_c).expect("recovered c hash"),
        ];
        assert_eq!(segment.overlap_start_height, 32);
        assert_eq!(segment.overlap_end_height, 33);
        assert_eq!(
            segment.overlap_root_hash,
            canonical_archived_recovered_history_segment_root(&overlap_hashes)
                .expect("overlap root hash")
        );
    }

    #[test]
    fn archived_recovered_history_segment_predecessor_validation_rejects_out_of_range_overlap() {
        let previous = ArchivedRecoveredHistorySegment {
            start_height: 40,
            end_height: 40,
            archived_profile_hash: sample_archived_recovered_history_profile_hash_for_tests(),
            archived_profile_activation_hash:
                sample_archived_recovered_history_profile_activation_hash_for_tests(),
            first_recovered_publication_bundle_hash: [115u8; 32],
            last_recovered_publication_bundle_hash: [115u8; 32],
            previous_archived_segment_hash: [0u8; 32],
            segment_root_hash: [116u8; 32],
            overlap_start_height: 0,
            overlap_end_height: 0,
            overlap_root_hash: [0u8; 32],
        };
        let mut current = ArchivedRecoveredHistorySegment {
            start_height: 41,
            end_height: 41,
            archived_profile_hash: sample_archived_recovered_history_profile_hash_for_tests(),
            archived_profile_activation_hash:
                sample_archived_recovered_history_profile_activation_hash_for_tests(),
            first_recovered_publication_bundle_hash: [117u8; 32],
            last_recovered_publication_bundle_hash: [117u8; 32],
            previous_archived_segment_hash: canonical_archived_recovered_history_segment_hash(
                &previous,
            )
            .expect("previous archived segment hash"),
            segment_root_hash: [118u8; 32],
            overlap_start_height: 41,
            overlap_end_height: 41,
            overlap_root_hash: [119u8; 32],
        };

        let error = validate_archived_recovered_history_segment_predecessor(&previous, &current)
            .expect_err("overlap outside predecessor coverage should fail");
        assert!(error.contains("does not cover the declared overlap anchor"));

        current.overlap_start_height = 0;
        current.overlap_end_height = 0;
        current.overlap_root_hash = [0u8; 32];
        validate_archived_recovered_history_segment_predecessor(&previous, &current)
            .expect("non-overlap predecessor should remain valid");
    }

    #[test]
    fn archived_recovered_history_segment_predecessor_validation_accepts_exact_overlap_page() {
        let previous = ArchivedRecoveredHistorySegment {
            start_height: 28,
            end_height: 30,
            archived_profile_hash: sample_archived_recovered_history_profile_hash_for_tests(),
            archived_profile_activation_hash:
                sample_archived_recovered_history_profile_activation_hash_for_tests(),
            first_recovered_publication_bundle_hash: [132u8; 32],
            last_recovered_publication_bundle_hash: [133u8; 32],
            previous_archived_segment_hash: [0u8; 32],
            segment_root_hash: [134u8; 32],
            overlap_start_height: 29,
            overlap_end_height: 30,
            overlap_root_hash: [135u8; 32],
        };
        let current = ArchivedRecoveredHistorySegment {
            start_height: 29,
            end_height: 31,
            archived_profile_hash: sample_archived_recovered_history_profile_hash_for_tests(),
            archived_profile_activation_hash:
                sample_archived_recovered_history_profile_activation_hash_for_tests(),
            first_recovered_publication_bundle_hash: [136u8; 32],
            last_recovered_publication_bundle_hash: [137u8; 32],
            previous_archived_segment_hash: canonical_archived_recovered_history_segment_hash(
                &previous,
            )
            .expect("previous archived segment hash"),
            segment_root_hash: [138u8; 32],
            overlap_start_height: 29,
            overlap_end_height: 30,
            overlap_root_hash: [139u8; 32],
        };

        validate_archived_recovered_history_segment_predecessor(&previous, &current)
            .expect("exact-overlap archived predecessor should remain valid");
    }

    #[test]
    fn archived_recovered_restart_page_range_matches_bounded_fold_page_geometry() {
        assert_eq!(
            archived_recovered_restart_page_range(30, 5, 2, 5, 4)
                .expect("archived recovered restart page range"),
            (1, 30)
        );
        assert_eq!(
            archived_recovered_restart_page_range(54, 5, 2, 5, 4)
                .expect("archived recovered restart page range"),
            (2, 54)
        );
    }

    #[test]
    fn archived_recovered_restart_page_builder_matches_segment_range() {
        let previous = ArchivedRecoveredHistorySegment {
            start_height: 50,
            end_height: 50,
            archived_profile_hash: sample_archived_recovered_history_profile_hash_for_tests(),
            archived_profile_activation_hash:
                sample_archived_recovered_history_profile_activation_hash_for_tests(),
            first_recovered_publication_bundle_hash: [120u8; 32],
            last_recovered_publication_bundle_hash: [120u8; 32],
            previous_archived_segment_hash: [0u8; 32],
            segment_root_hash: [121u8; 32],
            overlap_start_height: 0,
            overlap_end_height: 0,
            overlap_root_hash: [0u8; 32],
        };
        let segment = ArchivedRecoveredHistorySegment {
            start_height: 51,
            end_height: 51,
            archived_profile_hash: sample_archived_recovered_history_profile_hash_for_tests(),
            archived_profile_activation_hash:
                sample_archived_recovered_history_profile_activation_hash_for_tests(),
            first_recovered_publication_bundle_hash: [122u8; 32],
            last_recovered_publication_bundle_hash: [122u8; 32],
            previous_archived_segment_hash: canonical_archived_recovered_history_segment_hash(
                &previous,
            )
            .expect("previous archived segment hash"),
            segment_root_hash: [123u8; 32],
            overlap_start_height: 0,
            overlap_end_height: 0,
            overlap_root_hash: [0u8; 32],
        };
        let restart_entry = RecoveredRestartBlockHeaderEntry {
            certified_header: RecoveredCertifiedHeaderEntry {
                header: RecoveredCanonicalHeaderEntry {
                    height: 51,
                    view: 7,
                    canonical_block_commitment_hash: [124u8; 32],
                    parent_block_commitment_hash: [125u8; 32],
                    transactions_root_hash: [126u8; 32],
                    resulting_state_root_hash: [127u8; 32],
                    previous_canonical_collapse_commitment_hash: [128u8; 32],
                },
                certified_parent_quorum_certificate: QuorumCertificate {
                    height: 50,
                    view: 6,
                    block_hash: [125u8; 32],
                    ..Default::default()
                },
                certified_parent_resulting_state_root_hash: [129u8; 32],
            },
            header: BlockHeader {
                height: 51,
                view: 7,
                parent_hash: [125u8; 32],
                parent_state_root: StateRoot(vec![129u8; 32]),
                state_root: StateRoot(vec![127u8; 32]),
                transactions_root: vec![126u8; 32],
                timestamp: 1,
                timestamp_ms: 1_000,
                gas_used: 0,
                validator_set: Vec::new(),
                producer_account_id: AccountId([130u8; 32]),
                producer_key_suite: SignatureSuite::ED25519,
                producer_pubkey_hash: [131u8; 32],
                producer_pubkey: Vec::new(),
                oracle_counter: 0,
                oracle_trace_hash: [0u8; 32],
                parent_qc: QuorumCertificate {
                    height: 50,
                    view: 6,
                    block_hash: [125u8; 32],
                    ..Default::default()
                },
                previous_canonical_collapse_commitment_hash: [128u8; 32],
                canonical_collapse_extension_certificate: None,
                publication_frontier: None,
                guardian_certificate: None,
                sealed_finality_proof: None,
                canonical_order_certificate: None,
                timeout_certificate: None,
                signature: Vec::new(),
            },
        };

        let page =
            build_archived_recovered_restart_page(&segment, std::slice::from_ref(&restart_entry))
                .expect("archived recovered restart page");
        assert_eq!(page.start_height, 51);
        assert_eq!(page.end_height, 51);
        assert_eq!(
            page.segment_hash,
            canonical_archived_recovered_history_segment_hash(&segment).expect("segment hash")
        );
        assert_eq!(page.restart_headers, vec![restart_entry]);
    }

    #[test]
    fn canonical_collapse_historical_continuation_anchor_requires_all_hashes_or_none() {
        let mut collapse = CanonicalCollapseObject {
            height: 77,
            ..Default::default()
        };
        assert_eq!(
            canonical_collapse_historical_continuation_anchor(&collapse).expect("no anchor"),
            None
        );

        collapse.archived_recovered_history_checkpoint_hash = [0x11; 32];
        let error = canonical_collapse_historical_continuation_anchor(&collapse)
            .expect_err("partial anchor must fail");
        assert!(error.contains("all bootstrap hashes or none"));

        collapse.archived_recovered_history_profile_activation_hash = [0x22; 32];
        collapse.archived_recovered_history_retention_receipt_hash = [0x33; 32];
        let anchor = canonical_collapse_historical_continuation_anchor(&collapse)
            .expect("full anchor")
            .expect("present anchor");
        assert_eq!(anchor.checkpoint_hash, [0x11; 32]);
        assert_eq!(anchor.profile_activation_hash, [0x22; 32]);
        assert_eq!(anchor.retention_receipt_hash, [0x33; 32]);
    }

    #[test]
    fn canonical_replay_prefix_historical_continuation_anchor_matches_optional_triplet() {
        let mut entry = CanonicalReplayPrefixEntry {
            height: 91,
            ..Default::default()
        };
        assert_eq!(
            canonical_replay_prefix_historical_continuation_anchor(&entry).expect("no anchor"),
            None
        );

        entry.archived_recovered_history_checkpoint_hash = Some([0x41; 32]);
        entry.archived_recovered_history_profile_activation_hash = Some([0x42; 32]);
        entry.archived_recovered_history_retention_receipt_hash = Some([0x43; 32]);

        let anchor = canonical_replay_prefix_historical_continuation_anchor(&entry)
            .expect("full replay anchor")
            .expect("present replay anchor");
        assert_eq!(anchor.checkpoint_hash, [0x41; 32]);
        assert_eq!(anchor.profile_activation_hash, [0x42; 32]);
        assert_eq!(anchor.retention_receipt_hash, [0x43; 32]);
    }

    #[test]
    fn archived_recovered_history_checkpoint_builder_commits_segment_and_page_hashes() {
        let segment = ArchivedRecoveredHistorySegment {
            start_height: 51,
            end_height: 51,
            archived_profile_hash: sample_archived_recovered_history_profile_hash_for_tests(),
            archived_profile_activation_hash:
                sample_archived_recovered_history_profile_activation_hash_for_tests(),
            first_recovered_publication_bundle_hash: [140u8; 32],
            last_recovered_publication_bundle_hash: [140u8; 32],
            previous_archived_segment_hash: [0u8; 32],
            segment_root_hash: [141u8; 32],
            overlap_start_height: 0,
            overlap_end_height: 0,
            overlap_root_hash: [0u8; 32],
        };
        let restart_entry = RecoveredRestartBlockHeaderEntry {
            certified_header: RecoveredCertifiedHeaderEntry {
                header: RecoveredCanonicalHeaderEntry {
                    height: 51,
                    view: 7,
                    canonical_block_commitment_hash: [142u8; 32],
                    parent_block_commitment_hash: [143u8; 32],
                    transactions_root_hash: [144u8; 32],
                    resulting_state_root_hash: [145u8; 32],
                    previous_canonical_collapse_commitment_hash: [146u8; 32],
                },
                certified_parent_quorum_certificate: QuorumCertificate {
                    height: 50,
                    view: 6,
                    block_hash: [143u8; 32],
                    ..Default::default()
                },
                certified_parent_resulting_state_root_hash: [147u8; 32],
            },
            header: BlockHeader {
                height: 51,
                view: 7,
                parent_hash: [143u8; 32],
                parent_state_root: StateRoot(vec![147u8; 32]),
                state_root: StateRoot(vec![145u8; 32]),
                transactions_root: vec![144u8; 32],
                timestamp: 1,
                timestamp_ms: 1_000,
                gas_used: 0,
                validator_set: Vec::new(),
                producer_account_id: AccountId([148u8; 32]),
                producer_key_suite: SignatureSuite::ED25519,
                producer_pubkey_hash: [149u8; 32],
                producer_pubkey: Vec::new(),
                oracle_counter: 0,
                oracle_trace_hash: [0u8; 32],
                parent_qc: QuorumCertificate {
                    height: 50,
                    view: 6,
                    block_hash: [143u8; 32],
                    ..Default::default()
                },
                previous_canonical_collapse_commitment_hash: [146u8; 32],
                canonical_collapse_extension_certificate: None,
                publication_frontier: None,
                guardian_certificate: None,
                sealed_finality_proof: None,
                canonical_order_certificate: None,
                timeout_certificate: None,
                signature: Vec::new(),
            },
        };
        let page =
            build_archived_recovered_restart_page(&segment, std::slice::from_ref(&restart_entry))
                .expect("archived recovered restart page");

        let checkpoint = build_archived_recovered_history_checkpoint(&segment, &page, None)
            .expect("archived recovered history checkpoint");
        assert_eq!(checkpoint.covered_start_height, segment.start_height);
        assert_eq!(checkpoint.covered_end_height, segment.end_height);
        assert_eq!(
            checkpoint.latest_archived_segment_hash,
            canonical_archived_recovered_history_segment_hash(&segment).expect("segment hash")
        );
        assert_eq!(
            checkpoint.latest_archived_restart_page_hash,
            canonical_archived_recovered_restart_page_hash(&page).expect("page hash")
        );
        assert_eq!(checkpoint.previous_archived_checkpoint_hash, [0u8; 32]);
    }

    #[test]
    fn archived_recovered_history_checkpoint_builder_chains_previous_hash() {
        let previous_checkpoint = ArchivedRecoveredHistoryCheckpoint {
            covered_start_height: 28,
            covered_end_height: 50,
            archived_profile_hash: sample_archived_recovered_history_profile_hash_for_tests(),
            archived_profile_activation_hash:
                sample_archived_recovered_history_profile_activation_hash_for_tests(),
            latest_archived_segment_hash: [150u8; 32],
            latest_archived_restart_page_hash: [151u8; 32],
            previous_archived_checkpoint_hash: [0u8; 32],
        };
        let segment = ArchivedRecoveredHistorySegment {
            start_height: 29,
            end_height: 51,
            archived_profile_hash: sample_archived_recovered_history_profile_hash_for_tests(),
            archived_profile_activation_hash:
                sample_archived_recovered_history_profile_activation_hash_for_tests(),
            first_recovered_publication_bundle_hash: [152u8; 32],
            last_recovered_publication_bundle_hash: [153u8; 32],
            previous_archived_segment_hash: [154u8; 32],
            segment_root_hash: [155u8; 32],
            overlap_start_height: 29,
            overlap_end_height: 50,
            overlap_root_hash: [156u8; 32],
        };
        let page = ArchivedRecoveredRestartPage {
            segment_hash: canonical_archived_recovered_history_segment_hash(&segment)
                .expect("segment hash"),
            archived_profile_hash: segment.archived_profile_hash,
            archived_profile_activation_hash: segment.archived_profile_activation_hash,
            start_height: 29,
            end_height: 51,
            restart_headers: (29..=51)
                .map(|height| RecoveredRestartBlockHeaderEntry {
                    certified_header: RecoveredCertifiedHeaderEntry {
                        header: RecoveredCanonicalHeaderEntry {
                            height,
                            view: 7,
                            canonical_block_commitment_hash: [157u8; 32],
                            parent_block_commitment_hash: [158u8; 32],
                            transactions_root_hash: [159u8; 32],
                            resulting_state_root_hash: [160u8; 32],
                            previous_canonical_collapse_commitment_hash: [161u8; 32],
                        },
                        certified_parent_quorum_certificate: QuorumCertificate {
                            height: height.saturating_sub(1),
                            view: 6,
                            block_hash: [158u8; 32],
                            ..Default::default()
                        },
                        certified_parent_resulting_state_root_hash: [162u8; 32],
                    },
                    header: BlockHeader {
                        height,
                        view: 7,
                        parent_hash: [158u8; 32],
                        parent_state_root: StateRoot(vec![162u8; 32]),
                        state_root: StateRoot(vec![160u8; 32]),
                        transactions_root: vec![159u8; 32],
                        timestamp: 1,
                        timestamp_ms: 1_000,
                        gas_used: 0,
                        validator_set: Vec::new(),
                        producer_account_id: AccountId([163u8; 32]),
                        producer_key_suite: SignatureSuite::ED25519,
                        producer_pubkey_hash: [164u8; 32],
                        producer_pubkey: Vec::new(),
                        oracle_counter: 0,
                        oracle_trace_hash: [0u8; 32],
                        parent_qc: QuorumCertificate {
                            height: height.saturating_sub(1),
                            view: 6,
                            block_hash: [158u8; 32],
                            ..Default::default()
                        },
                        previous_canonical_collapse_commitment_hash: [161u8; 32],
                        canonical_collapse_extension_certificate: None,
                        publication_frontier: None,
                        guardian_certificate: None,
                        sealed_finality_proof: None,
                        canonical_order_certificate: None,
                        timeout_certificate: None,
                        signature: Vec::new(),
                    },
                })
                .collect(),
        };

        let checkpoint = build_archived_recovered_history_checkpoint(
            &segment,
            &page,
            Some(&previous_checkpoint),
        )
        .expect("chained archived recovered history checkpoint");
        assert_eq!(
            checkpoint.previous_archived_checkpoint_hash,
            canonical_archived_recovered_history_checkpoint_hash(&previous_checkpoint)
                .expect("previous checkpoint hash")
        );
    }

    #[test]
    fn archived_recovered_history_retention_receipt_builder_commits_checkpoint_and_validator_set() {
        let checkpoint = ArchivedRecoveredHistoryCheckpoint {
            covered_start_height: 41,
            covered_end_height: 63,
            archived_profile_hash: sample_archived_recovered_history_profile_hash_for_tests(),
            archived_profile_activation_hash:
                sample_archived_recovered_history_profile_activation_hash_for_tests(),
            latest_archived_segment_hash: [170u8; 32],
            latest_archived_restart_page_hash: [171u8; 32],
            previous_archived_checkpoint_hash: [169u8; 32],
        };
        let validator_sets = ValidatorSetsV1 {
            current: ValidatorSetV1 {
                effective_from_height: 1,
                total_weight: 3,
                validators: vec![
                    ValidatorV1 {
                        account_id: AccountId([0x11; 32]),
                        weight: 1,
                        consensus_key: Default::default(),
                    },
                    ValidatorV1 {
                        account_id: AccountId([0x22; 32]),
                        weight: 2,
                        consensus_key: Default::default(),
                    },
                ],
            },
            next: None,
        };
        let validator_set_commitment_hash =
            canonical_validator_sets_hash(&validator_sets).expect("validator set commitment hash");

        let receipt = build_archived_recovered_history_retention_receipt(
            &checkpoint,
            validator_set_commitment_hash,
            96,
        )
        .expect("archived recovered-history retention receipt");

        assert_eq!(
            receipt.covered_start_height,
            checkpoint.covered_start_height
        );
        assert_eq!(receipt.covered_end_height, checkpoint.covered_end_height);
        assert_eq!(
            receipt.archived_checkpoint_hash,
            canonical_archived_recovered_history_checkpoint_hash(&checkpoint)
                .expect("checkpoint hash")
        );
        assert_eq!(
            receipt.validator_set_commitment_hash,
            validator_set_commitment_hash
        );
        assert_eq!(receipt.retained_through_height, 96);
        assert_ne!(
            canonical_archived_recovered_history_retention_receipt_hash(&receipt)
                .expect("receipt hash"),
            [0u8; 32]
        );
    }

    #[test]
    fn archived_recovered_history_retention_receipt_builder_rejects_short_horizon() {
        let checkpoint = ArchivedRecoveredHistoryCheckpoint {
            covered_start_height: 71,
            covered_end_height: 93,
            archived_profile_hash: sample_archived_recovered_history_profile_hash_for_tests(),
            archived_profile_activation_hash:
                sample_archived_recovered_history_profile_activation_hash_for_tests(),
            latest_archived_segment_hash: [180u8; 32],
            latest_archived_restart_page_hash: [181u8; 32],
            previous_archived_checkpoint_hash: [179u8; 32],
        };

        let error =
            build_archived_recovered_history_retention_receipt(&checkpoint, [182u8; 32], 92)
                .expect_err("short retention horizon must fail");
        assert!(error.contains("retained-through height"));
    }

    #[test]
    fn archived_recovered_history_profile_builder_commits_archive_geometry() {
        let profile = build_archived_recovered_history_profile(
            1024,
            5,
            2,
            5,
            4,
            ArchivedRecoveredHistoryCheckpointUpdateRule::EveryPublishedSegmentV1,
        )
        .expect("archived recovered-history profile");
        assert_eq!(profile.retention_horizon, 1024);
        assert_eq!(profile.restart_page_window, 5);
        assert_eq!(profile.restart_page_overlap, 2);
        assert_eq!(profile.windows_per_segment, 5);
        assert_eq!(profile.segments_per_fold, 4);
        assert_eq!(
            canonical_archived_recovered_history_profile_hash(&profile)
                .expect("archived recovered-history profile hash"),
            canonical_archived_recovered_history_profile_hash(&profile)
                .expect("deterministic archived recovered-history profile hash")
        );
    }

    #[test]
    fn archived_recovered_history_profile_builder_rejects_zero_retention_horizon() {
        let error = build_archived_recovered_history_profile(
            0,
            5,
            2,
            5,
            4,
            ArchivedRecoveredHistoryCheckpointUpdateRule::EveryPublishedSegmentV1,
        )
        .expect_err("zero archived retention horizon must fail");
        assert!(error.contains("non-zero retention horizon"));
    }

    #[test]
    fn recoverable_slot_payload_v4_lifts_from_v3_and_preserves_bundle() {
        let (payload_v3, bundle) = build_sample_recoverable_slot_payload_v3(21, 9, 44);
        let (payload_v4, lifted_bundle, bulletin_close) =
            lift_recoverable_slot_payload_v3_to_v4(&payload_v3).expect("lift payload v4");

        assert_eq!(lifted_bundle, bundle);
        assert_eq!(payload_v4.height, payload_v3.height);
        assert_eq!(payload_v4.view, payload_v3.view);
        assert_eq!(
            payload_v4.producer_account_id,
            payload_v3.producer_account_id
        );
        assert_eq!(
            payload_v4.block_commitment_hash,
            payload_v3.block_commitment_hash
        );
        assert_eq!(
            payload_v4.canonical_order_certificate,
            payload_v3.canonical_order_certificate
        );
        assert_eq!(
            payload_v4.ordered_transaction_bytes,
            payload_v3.ordered_transaction_bytes
        );
        assert_eq!(
            payload_v4.canonical_order_publication_bundle_bytes,
            payload_v3.canonical_order_publication_bundle_bytes
        );
        let decoded_close: CanonicalBulletinClose =
            codec::from_bytes_canonical(&payload_v4.canonical_bulletin_close_bytes)
                .expect("decode bulletin close");
        assert_eq!(decoded_close, bulletin_close);
    }

    #[test]
    fn recoverable_slot_payload_v5_lifts_from_v4_and_extracts_surface() {
        let (payload_v4, bundle, bulletin_close) =
            build_sample_recoverable_slot_payload_v4(22, 10, 47);
        let (payload_v5, lifted_bundle, lifted_close, surface) =
            lift_recoverable_slot_payload_v4_to_v5(&payload_v4).expect("lift payload v5");

        assert_eq!(lifted_bundle, bundle);
        assert_eq!(lifted_close, bulletin_close);
        assert_eq!(payload_v5.height, payload_v4.height);
        assert_eq!(payload_v5.view, payload_v4.view);
        assert_eq!(
            payload_v5.producer_account_id,
            payload_v4.producer_account_id
        );
        assert_eq!(
            payload_v5.block_commitment_hash,
            payload_v4.block_commitment_hash
        );
        assert_eq!(
            payload_v5.canonical_order_certificate,
            payload_v4.canonical_order_certificate
        );
        assert_eq!(
            payload_v5.ordered_transaction_bytes,
            payload_v4.ordered_transaction_bytes
        );
        assert_eq!(
            payload_v5.canonical_order_publication_bundle_bytes,
            payload_v4.canonical_order_publication_bundle_bytes
        );
        assert_eq!(
            payload_v5.canonical_bulletin_close_bytes,
            payload_v4.canonical_bulletin_close_bytes
        );
        let decoded_availability: BulletinAvailabilityCertificate = codec::from_bytes_canonical(
            &payload_v5.canonical_bulletin_availability_certificate_bytes,
        )
        .expect("decode bulletin availability");
        assert_eq!(
            decoded_availability,
            bundle.bulletin_availability_certificate
        );
        assert_eq!(payload_v5.bulletin_surface_entries, surface);
        assert_eq!(surface, bundle.bulletin_entries);
    }

    #[test]
    fn recovered_surface_derives_close_valued_canonical_collapse_object() {
        let (payload_v5, _, bulletin_close, _) =
            build_sample_recoverable_slot_payload_v5(2, 10, 47);
        let previous = sample_canonical_collapse_object(1, None, 91);

        let collapse = derive_canonical_collapse_object_from_recovered_surface(
            &payload_v5,
            &bulletin_close,
            Some(&previous),
        )
        .expect("derive recovered collapse");

        assert_eq!(collapse.height, payload_v5.height);
        assert_eq!(collapse.ordering.kind, CanonicalCollapseKind::Close);
        assert_eq!(
            collapse.transactions_root_hash,
            payload_v5
                .canonical_order_certificate
                .ordered_transactions_root_hash
        );
        assert_eq!(
            collapse.resulting_state_root_hash,
            payload_v5
                .canonical_order_certificate
                .resulting_state_root_hash
        );
        verify_canonical_collapse_continuity(&collapse, Some(&previous))
            .expect("recovered close continuity should verify");
    }

    #[test]
    fn recovered_surface_derives_abort_valued_canonical_collapse_object_for_omissions() {
        let (mut payload_v5, _, bulletin_close, _) =
            build_sample_recoverable_slot_payload_v5(3, 11, 48);
        payload_v5
            .canonical_order_certificate
            .omission_proofs
            .push(OmissionProof {
                height: payload_v5.height,
                tx_hash: [0xA7u8; 32],
                offender_account_id: AccountId([0x91u8; 32]),
                bulletin_root: [0xB3u8; 32],
                details: "recovered omission proof".into(),
            });
        let grandparent = sample_canonical_collapse_object(1, None, 92);
        let previous = sample_canonical_collapse_object(2, Some(&grandparent), 93);

        let collapse = derive_canonical_collapse_object_from_recovered_surface(
            &payload_v5,
            &bulletin_close,
            Some(&previous),
        )
        .expect("derive recovered omission collapse");

        assert_eq!(collapse.height, payload_v5.height);
        assert_eq!(collapse.ordering.kind, CanonicalCollapseKind::Abort);
        verify_canonical_collapse_continuity(&collapse, Some(&previous))
            .expect("recovered abort continuity should verify");
    }

    #[test]
    fn recoverable_slot_payload_v3_reconstructs_from_two_systematic_xor_shares() {
        let (payload, bundle) = build_sample_recoverable_slot_payload_v3(15, 7, 71);
        let shards = encode_systematic_xor_k_of_k_plus_1_shards(&payload, 2);
        let materials = vec![
            RecoveryShareMaterial {
                height: payload.height,
                witness_manifest_hash: [72u8; 32],
                block_commitment_hash: payload.block_commitment_hash,
                coding: xor_recovery_coding(3, 2),
                share_index: 0,
                share_commitment_hash: [73u8; 32],
                material_bytes: shards[0].clone(),
            },
            RecoveryShareMaterial {
                height: payload.height,
                witness_manifest_hash: [74u8; 32],
                block_commitment_hash: payload.block_commitment_hash,
                coding: xor_recovery_coding(3, 2),
                share_index: 2,
                share_commitment_hash: [75u8; 32],
                material_bytes: shards[2].clone(),
            },
        ];

        let reconstructed = recover_recoverable_slot_payload_v3_from_share_materials(&materials)
            .expect("recoverable slot payload should reconstruct from two systematic xor shares");
        assert_eq!(reconstructed, payload);

        let (recovered_payload, recovered_bundle) =
            recover_canonical_order_publication_bundle_from_share_materials(&materials)
                .expect("publication bundle should reconstruct");
        assert_eq!(recovered_payload, payload);
        assert_eq!(recovered_bundle, bundle);
        assert_eq!(
            canonical_order_publication_bundle_hash(&recovered_bundle)
                .expect("publication bundle hash"),
            canonical_order_publication_bundle_hash(&bundle).expect("expected bundle hash")
        );
    }

    #[test]
    fn recoverable_slot_payload_v3_reconstructs_from_three_of_four_systematic_xor_parity_shares() {
        let (payload, bundle) = build_sample_recoverable_slot_payload_v3(16, 8, 76);
        let shards = encode_systematic_xor_k_of_k_plus_1_shards(&payload, 3);
        let materials = vec![
            RecoveryShareMaterial {
                height: payload.height,
                witness_manifest_hash: [77u8; 32],
                block_commitment_hash: payload.block_commitment_hash,
                coding: xor_recovery_coding(4, 3),
                share_index: 0,
                share_commitment_hash: [78u8; 32],
                material_bytes: shards[0].clone(),
            },
            RecoveryShareMaterial {
                height: payload.height,
                witness_manifest_hash: [79u8; 32],
                block_commitment_hash: payload.block_commitment_hash,
                coding: xor_recovery_coding(4, 3),
                share_index: 2,
                share_commitment_hash: [80u8; 32],
                material_bytes: shards[2].clone(),
            },
            RecoveryShareMaterial {
                height: payload.height,
                witness_manifest_hash: [81u8; 32],
                block_commitment_hash: payload.block_commitment_hash,
                coding: xor_recovery_coding(4, 3),
                share_index: 3,
                share_commitment_hash: [82u8; 32],
                material_bytes: shards[3].clone(),
            },
        ];

        let reconstructed = recover_recoverable_slot_payload_v3_from_share_materials(&materials)
            .expect(
            "recoverable slot payload should reconstruct from three of four parity-family shares",
        );
        assert_eq!(reconstructed, payload);

        let (recovered_payload, recovered_bundle) =
            recover_canonical_order_publication_bundle_from_share_materials(&materials)
                .expect("publication bundle should reconstruct");
        assert_eq!(recovered_payload, payload);
        assert_eq!(recovered_bundle, bundle);
    }

    #[test]
    fn recoverable_slot_payload_v3_reconstructs_from_two_of_four_systematic_gf256_shares() {
        let (payload, bundle) = build_sample_recoverable_slot_payload_v3(17, 9, 83);
        let shards = encode_systematic_gf256_2_of_4_shards(&payload);
        let materials = vec![
            RecoveryShareMaterial {
                height: payload.height,
                witness_manifest_hash: [84u8; 32],
                block_commitment_hash: payload.block_commitment_hash,
                coding: gf256_recovery_coding(4, 2),
                share_index: 1,
                share_commitment_hash: [85u8; 32],
                material_bytes: shards[1].clone(),
            },
            RecoveryShareMaterial {
                height: payload.height,
                witness_manifest_hash: [86u8; 32],
                block_commitment_hash: payload.block_commitment_hash,
                coding: gf256_recovery_coding(4, 2),
                share_index: 3,
                share_commitment_hash: [87u8; 32],
                material_bytes: shards[3].clone(),
            },
        ];

        let reconstructed = recover_recoverable_slot_payload_v3_from_share_materials(&materials)
            .expect("recoverable slot payload should reconstruct from two of four gf256 shares");
        assert_eq!(reconstructed, payload);

        let (recovered_payload, recovered_bundle) =
            recover_canonical_order_publication_bundle_from_share_materials(&materials)
                .expect("publication bundle should reconstruct");
        assert_eq!(recovered_payload, payload);
        assert_eq!(recovered_bundle, bundle);
    }

    #[test]
    fn recoverable_slot_payload_v3_reconstructs_from_three_of_five_systematic_gf256_shares() {
        let (payload, bundle) = build_sample_recoverable_slot_payload_v3(18, 10, 88);
        let shards = encode_systematic_gf256_3_of_5_shards(&payload);
        let materials = vec![
            RecoveryShareMaterial {
                height: payload.height,
                witness_manifest_hash: [89u8; 32],
                block_commitment_hash: payload.block_commitment_hash,
                coding: gf256_recovery_coding(5, 3),
                share_index: 0,
                share_commitment_hash: [90u8; 32],
                material_bytes: shards[0].clone(),
            },
            RecoveryShareMaterial {
                height: payload.height,
                witness_manifest_hash: [91u8; 32],
                block_commitment_hash: payload.block_commitment_hash,
                coding: gf256_recovery_coding(5, 3),
                share_index: 3,
                share_commitment_hash: [92u8; 32],
                material_bytes: shards[3].clone(),
            },
            RecoveryShareMaterial {
                height: payload.height,
                witness_manifest_hash: [93u8; 32],
                block_commitment_hash: payload.block_commitment_hash,
                coding: gf256_recovery_coding(5, 3),
                share_index: 4,
                share_commitment_hash: [94u8; 32],
                material_bytes: shards[4].clone(),
            },
        ];

        let reconstructed = recover_recoverable_slot_payload_v3_from_share_materials(&materials)
            .expect("recoverable slot payload should reconstruct from three of five gf256 shares");
        assert_eq!(reconstructed, payload);

        let (recovered_payload, recovered_bundle) =
            recover_canonical_order_publication_bundle_from_share_materials(&materials)
                .expect("publication bundle should reconstruct");
        assert_eq!(recovered_payload, payload);
        assert_eq!(recovered_bundle, bundle);
    }

    #[test]
    fn recoverable_slot_payload_v3_reconstructs_from_three_of_seven_systematic_gf256_shares() {
        let (payload, bundle) = build_sample_recoverable_slot_payload_v3(19, 11, 95);
        let shards = encode_systematic_gf256_3_of_7_shards(&payload);
        let materials = vec![
            RecoveryShareMaterial {
                height: payload.height,
                witness_manifest_hash: [96u8; 32],
                block_commitment_hash: payload.block_commitment_hash,
                coding: gf256_recovery_coding(7, 3),
                share_index: 0,
                share_commitment_hash: [97u8; 32],
                material_bytes: shards[0].clone(),
            },
            RecoveryShareMaterial {
                height: payload.height,
                witness_manifest_hash: [98u8; 32],
                block_commitment_hash: payload.block_commitment_hash,
                coding: gf256_recovery_coding(7, 3),
                share_index: 3,
                share_commitment_hash: [99u8; 32],
                material_bytes: shards[3].clone(),
            },
            RecoveryShareMaterial {
                height: payload.height,
                witness_manifest_hash: [100u8; 32],
                block_commitment_hash: payload.block_commitment_hash,
                coding: gf256_recovery_coding(7, 3),
                share_index: 6,
                share_commitment_hash: [101u8; 32],
                material_bytes: shards[6].clone(),
            },
        ];

        let reconstructed = recover_recoverable_slot_payload_v3_from_share_materials(&materials)
            .expect("recoverable slot payload should reconstruct from three of seven gf256 shares");
        assert_eq!(reconstructed, payload);

        let (recovered_payload, recovered_bundle) =
            recover_canonical_order_publication_bundle_from_share_materials(&materials)
                .expect("publication bundle should reconstruct");
        assert_eq!(recovered_payload, payload);
        assert_eq!(recovered_bundle, bundle);
    }

    #[test]
    fn recoverable_slot_payload_v3_reconstructs_from_four_of_six_systematic_gf256_shares() {
        let (payload, bundle) = build_sample_recoverable_slot_payload_v3(20, 12, 102);
        let shards = encode_systematic_gf256_4_of_6_shards(&payload);
        let materials = vec![
            RecoveryShareMaterial {
                height: payload.height,
                witness_manifest_hash: [103u8; 32],
                block_commitment_hash: payload.block_commitment_hash,
                coding: gf256_recovery_coding(6, 4),
                share_index: 0,
                share_commitment_hash: [104u8; 32],
                material_bytes: shards[0].clone(),
            },
            RecoveryShareMaterial {
                height: payload.height,
                witness_manifest_hash: [105u8; 32],
                block_commitment_hash: payload.block_commitment_hash,
                coding: gf256_recovery_coding(6, 4),
                share_index: 2,
                share_commitment_hash: [106u8; 32],
                material_bytes: shards[2].clone(),
            },
            RecoveryShareMaterial {
                height: payload.height,
                witness_manifest_hash: [107u8; 32],
                block_commitment_hash: payload.block_commitment_hash,
                coding: gf256_recovery_coding(6, 4),
                share_index: 4,
                share_commitment_hash: [108u8; 32],
                material_bytes: shards[4].clone(),
            },
            RecoveryShareMaterial {
                height: payload.height,
                witness_manifest_hash: [109u8; 32],
                block_commitment_hash: payload.block_commitment_hash,
                coding: gf256_recovery_coding(6, 4),
                share_index: 5,
                share_commitment_hash: [110u8; 32],
                material_bytes: shards[5].clone(),
            },
        ];

        let reconstructed = recover_recoverable_slot_payload_v3_from_share_materials(&materials)
            .expect("recoverable slot payload should reconstruct from four of six gf256 shares");
        assert_eq!(reconstructed, payload);

        let (recovered_payload, recovered_bundle) =
            recover_canonical_order_publication_bundle_from_share_materials(&materials)
                .expect("publication bundle should reconstruct");
        assert_eq!(recovered_payload, payload);
        assert_eq!(recovered_bundle, bundle);
    }

    #[test]
    fn recoverable_slot_payload_v3_reconstructs_from_four_of_seven_systematic_gf256_shares() {
        let (payload, bundle) = build_sample_recoverable_slot_payload_v3(21, 13, 111);
        let shards = encode_systematic_gf256_4_of_7_shards(&payload);
        let materials = vec![
            RecoveryShareMaterial {
                height: payload.height,
                witness_manifest_hash: [112u8; 32],
                block_commitment_hash: payload.block_commitment_hash,
                coding: gf256_recovery_coding(7, 4),
                share_index: 0,
                share_commitment_hash: [113u8; 32],
                material_bytes: shards[0].clone(),
            },
            RecoveryShareMaterial {
                height: payload.height,
                witness_manifest_hash: [114u8; 32],
                block_commitment_hash: payload.block_commitment_hash,
                coding: gf256_recovery_coding(7, 4),
                share_index: 2,
                share_commitment_hash: [115u8; 32],
                material_bytes: shards[2].clone(),
            },
            RecoveryShareMaterial {
                height: payload.height,
                witness_manifest_hash: [116u8; 32],
                block_commitment_hash: payload.block_commitment_hash,
                coding: gf256_recovery_coding(7, 4),
                share_index: 4,
                share_commitment_hash: [117u8; 32],
                material_bytes: shards[4].clone(),
            },
            RecoveryShareMaterial {
                height: payload.height,
                witness_manifest_hash: [118u8; 32],
                block_commitment_hash: payload.block_commitment_hash,
                coding: gf256_recovery_coding(7, 4),
                share_index: 6,
                share_commitment_hash: [119u8; 32],
                material_bytes: shards[6].clone(),
            },
        ];

        let reconstructed = recover_recoverable_slot_payload_v3_from_share_materials(&materials)
            .expect("recoverable slot payload should reconstruct from four of seven gf256 shares");
        assert_eq!(reconstructed, payload);

        let (recovered_payload, recovered_bundle) =
            recover_canonical_order_publication_bundle_from_share_materials(&materials)
                .expect("publication bundle should reconstruct");
        assert_eq!(recovered_payload, payload);
        assert_eq!(recovered_bundle, bundle);
    }

    #[test]
    fn coded_recovery_family_contract_conformance_holds_across_supported_families() {
        for (height, view, seed, coding) in [
            (30, 14, 0x41, xor_recovery_coding(3, 2)),
            (31, 15, 0x47, xor_recovery_coding(4, 3)),
            (32, 16, 0x53, gf256_recovery_coding(4, 2)),
            (33, 17, 0x59, gf256_recovery_coding(5, 3)),
            (34, 18, 0x61, gf256_recovery_coding(7, 3)),
            (35, 19, 0x67, gf256_recovery_coding(7, 4)),
        ] {
            assert_coded_recovery_family_contract_conformance_case(height, view, seed, coding);
        }
    }

    #[test]
    fn derive_canonical_collapse_object_returns_order_abort_without_certificate() {
        let header = BlockHeader {
            height: 23,
            view: 3,
            parent_hash: [51u8; 32],
            parent_state_root: StateRoot(vec![1u8; 32]),
            state_root: StateRoot(vec![2u8; 32]),
            transactions_root: vec![3u8; 32],
            timestamp: 1_750_001_111,
            timestamp_ms: 1_750_001_111_000,
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
            publication_frontier: None,
            guardian_certificate: None,
            sealed_finality_proof: None,
            canonical_order_certificate: None,
            timeout_certificate: None,
        };

        let collapse =
            derive_canonical_collapse_object(&header, &[]).expect("derive collapse object");
        assert_eq!(collapse.height, header.height);
        assert_eq!(
            collapse.previous_canonical_collapse_commitment_hash,
            [0u8; 32]
        );
        assert_eq!(collapse.ordering.kind, CanonicalCollapseKind::Abort);
        assert!(collapse.sealing.is_none());
        assert_eq!(
            collapse.transactions_root_hash,
            to_root_hash(&header.transactions_root).unwrap()
        );
        assert_eq!(
            collapse.resulting_state_root_hash,
            to_root_hash(&header.state_root.0).unwrap()
        );
    }

    #[test]
    fn derive_canonical_collapse_object_binds_order_close_and_sealed_close() {
        let base_header = BlockHeader {
            height: 29,
            view: 5,
            parent_hash: [61u8; 32],
            parent_state_root: StateRoot(vec![1u8; 32]),
            state_root: StateRoot(vec![2u8; 32]),
            transactions_root: vec![],
            timestamp: 1_750_001_222,
            timestamp_ms: 1_750_001_222_000,
            gas_used: 0,
            validator_set: Vec::new(),
            producer_account_id: AccountId([23u8; 32]),
            producer_key_suite: SignatureSuite::ED25519,
            producer_pubkey_hash: [24u8; 32],
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
                account_id: AccountId([25u8; 32]),
                nonce: 1,
                chain_id: ChainId(1),
                tx_version: 1,
                session_auth: None,
            },
            payload: SystemPayload::CallService {
                service_id: "guardian_registry".into(),
                method: "publish_aft_bulletin_commitment@v1".into(),
                params: vec![7],
            },
            signature_proof: SignatureProof::default(),
        }));
        let tx_two = ChainTransaction::System(Box::new(SystemTransaction {
            header: SignHeader {
                account_id: AccountId([26u8; 32]),
                nonce: 1,
                chain_id: ChainId(1),
                tx_version: 1,
                session_auth: None,
            },
            payload: SystemPayload::CallService {
                service_id: "guardian_registry".into(),
                method: "publish_aft_canonical_order_artifact_bundle@v1".into(),
                params: vec![8],
            },
            signature_proof: SignatureProof::default(),
        }));
        let ordered_transactions =
            canonicalize_transactions_for_header(&base_header, &[tx_one, tx_two])
                .expect("canonicalized transactions");
        let tx_hashes: Vec<[u8; 32]> = ordered_transactions
            .iter()
            .map(|tx| tx.hash().expect("tx hash"))
            .collect();

        let mut header = base_header;
        header.transactions_root =
            canonical_transaction_root_from_hashes(&tx_hashes).expect("transactions root");
        let certificate =
            build_committed_surface_canonical_order_certificate(&header, &ordered_transactions)
                .expect("build committed-surface certificate");
        header.canonical_order_certificate = Some(certificate.clone());
        header.state_root = StateRoot(certificate.resulting_state_root_hash.to_vec());

        let transcripts_root = canonical_asymptote_observer_transcripts_hash(&[]).unwrap();
        let challenges_root = canonical_asymptote_observer_challenges_hash(&[]).unwrap();
        let canonical_close = AsymptoteObserverCanonicalClose {
            epoch: 9,
            height: header.height,
            view: header.view,
            assignments_hash: [91u8; 32],
            transcripts_root,
            challenges_root,
            transcript_count: 0,
            challenge_count: 0,
            challenge_cutoff_timestamp_ms: 1_750_001_333,
        };
        let sealed_finality_proof = SealedFinalityProof {
            epoch: 9,
            finality_tier: FinalityTier::SealedFinal,
            collapse_state: CollapseState::SealedFinal,
            guardian_manifest_hash: [92u8; 32],
            guardian_decision_hash: [93u8; 32],
            guardian_counter: 3,
            guardian_trace_hash: [94u8; 32],
            guardian_measurement_root: [95u8; 32],
            policy_hash: [96u8; 32],
            witness_certificates: Vec::new(),
            observer_certificates: Vec::new(),
            observer_close_certificate: None,
            observer_transcripts: Vec::new(),
            observer_challenges: Vec::new(),
            observer_transcript_commitment: None,
            observer_challenge_commitment: None,
            observer_canonical_close: Some(canonical_close.clone()),
            observer_canonical_abort: None,
            veto_proofs: Vec::new(),
            divergence_signals: Vec::new(),
            proof_signature: SignatureProof::default(),
        };
        header.sealed_finality_proof = Some(sealed_finality_proof);

        let collapse = derive_canonical_collapse_object(&header, &ordered_transactions)
            .expect("derive collapse object");
        assert_eq!(collapse.ordering.kind, CanonicalCollapseKind::Close);
        assert_eq!(
            collapse.ordering.canonical_order_certificate_hash,
            canonical_order_certificate_hash(&certificate).unwrap()
        );
        let sealing = collapse.sealing.clone().expect("sealing collapse");
        assert_eq!(sealing.kind, CanonicalCollapseKind::Close);
        assert_eq!(sealing.collapse_state, CollapseState::SealedFinal);
        assert_eq!(
            sealing.resolution_hash,
            canonical_asymptote_observer_canonical_close_hash(&canonical_close).unwrap()
        );
        assert_eq!(
            canonical_collapse_object_hash(&collapse).unwrap(),
            canonical_collapse_object_hash(&collapse).unwrap()
        );
    }

    #[test]
    fn derive_canonical_collapse_object_binds_previous_collapse_hash() {
        let previous = CanonicalCollapseObject {
            height: 6,
            previous_canonical_collapse_commitment_hash: [0u8; 32],
            continuity_accumulator_hash: [0u8; 32],
            continuity_recursive_proof: Default::default(),
            ordering: CanonicalOrderingCollapse {
                height: 6,
                kind: CanonicalCollapseKind::Close,
                bulletin_commitment_hash: [1u8; 32],
                bulletin_availability_certificate_hash: [2u8; 32],
                bulletin_retrievability_profile_hash: [0u8; 32],
                bulletin_shard_manifest_hash: [0u8; 32],
                bulletin_custody_receipt_hash: [0u8; 32],
                bulletin_close_hash: [3u8; 32],
                canonical_order_certificate_hash: [4u8; 32],
            },
            sealing: None,
            transactions_root_hash: [5u8; 32],
            resulting_state_root_hash: [6u8; 32],
            archived_recovered_history_checkpoint_hash: [0u8; 32],
            archived_recovered_history_profile_activation_hash: [0u8; 32],
            archived_recovered_history_retention_receipt_hash: [0u8; 32],
        };
        let mut previous = previous;
        bind_canonical_collapse_continuity(&mut previous, None).expect("bind previous continuity");
        let header = BlockHeader {
            height: 7,
            view: 2,
            parent_hash: [9u8; 32],
            parent_state_root: StateRoot(previous.resulting_state_root_hash.to_vec()),
            state_root: StateRoot(vec![2u8; 32]),
            transactions_root: vec![3u8; 32],
            timestamp: 1_750_000_123,
            timestamp_ms: 1_750_000_123_000,
            gas_used: 0,
            validator_set: vec![vec![4u8; 32]],
            producer_account_id: AccountId([5u8; 32]),
            producer_key_suite: SignatureSuite::ED25519,
            producer_pubkey_hash: [6u8; 32],
            producer_pubkey: vec![7u8; 32],
            oracle_counter: 1,
            oracle_trace_hash: [8u8; 32],
            guardian_certificate: None,
            sealed_finality_proof: None,
            canonical_order_certificate: None,
            timeout_certificate: None,
            parent_qc: QuorumCertificate::default(),
            previous_canonical_collapse_commitment_hash:
                canonical_collapse_commitment_hash_from_object(&previous)
                    .expect("previous canonical collapse commitment hash"),
            canonical_collapse_extension_certificate: Some(certificate_from_predecessor(&previous)),
            publication_frontier: None,
            signature: vec![],
        };
        let collapse =
            derive_canonical_collapse_object_with_previous(&header, &[], Some(&previous))
                .expect("derive continuity-bound collapse");
        let previous_hash =
            canonical_collapse_commitment_hash_from_object(&previous).expect("previous hash");
        assert_eq!(
            collapse.previous_canonical_collapse_commitment_hash,
            previous_hash
        );
        verify_canonical_collapse_continuity(&collapse, Some(&previous))
            .expect("continuity should verify");
        assert_eq!(
            expected_previous_canonical_collapse_commitment_hash(collapse.height, Some(&previous))
                .unwrap(),
            previous_hash
        );
    }

    #[test]
    fn block_header_canonical_collapse_evidence_requires_carried_certificate() {
        let previous = CanonicalCollapseObject {
            height: 1,
            previous_canonical_collapse_commitment_hash: [0u8; 32],
            continuity_accumulator_hash: [0u8; 32],
            continuity_recursive_proof: Default::default(),
            ordering: CanonicalOrderingCollapse {
                height: 6,
                kind: CanonicalCollapseKind::Close,
                bulletin_commitment_hash: [11u8; 32],
                bulletin_availability_certificate_hash: [12u8; 32],
                bulletin_retrievability_profile_hash: [0u8; 32],
                bulletin_shard_manifest_hash: [0u8; 32],
                bulletin_custody_receipt_hash: [0u8; 32],
                bulletin_close_hash: [13u8; 32],
                canonical_order_certificate_hash: [14u8; 32],
            },
            sealing: None,
            transactions_root_hash: [15u8; 32],
            resulting_state_root_hash: [16u8; 32],
            archived_recovered_history_checkpoint_hash: [0u8; 32],
            archived_recovered_history_profile_activation_hash: [0u8; 32],
            archived_recovered_history_retention_receipt_hash: [0u8; 32],
        };
        let mut previous = previous;
        bind_canonical_collapse_continuity(&mut previous, None).expect("bind previous continuity");
        let header = BlockHeader {
            height: 2,
            view: 0,
            parent_hash: [17u8; 32],
            parent_state_root: StateRoot(previous.resulting_state_root_hash.to_vec()),
            state_root: StateRoot(vec![18u8; 32]),
            transactions_root: vec![19u8; 32],
            timestamp: 1,
            timestamp_ms: 1_000,
            gas_used: 0,
            validator_set: vec![vec![20u8; 32]],
            producer_account_id: AccountId([21u8; 32]),
            producer_key_suite: SignatureSuite::ED25519,
            producer_pubkey_hash: [22u8; 32],
            producer_pubkey: vec![23u8; 32],
            oracle_counter: 0,
            oracle_trace_hash: [24u8; 32],
            guardian_certificate: None,
            sealed_finality_proof: None,
            canonical_order_certificate: None,
            timeout_certificate: None,
            parent_qc: QuorumCertificate::default(),
            previous_canonical_collapse_commitment_hash:
                canonical_collapse_commitment_hash_from_object(&previous).unwrap(),
            canonical_collapse_extension_certificate: None,
            publication_frontier: None,
            signature: vec![],
        };

        assert!(verify_block_header_canonical_collapse_evidence(&header, Some(&previous)).is_err());
    }

    #[test]
    fn block_header_canonical_collapse_evidence_rejects_missing_previous_anchor() {
        let previous = CanonicalCollapseObject {
            height: 1,
            previous_canonical_collapse_commitment_hash: [0u8; 32],
            continuity_accumulator_hash: [0u8; 32],
            continuity_recursive_proof: Default::default(),
            ordering: CanonicalOrderingCollapse {
                height: 1,
                kind: CanonicalCollapseKind::Close,
                bulletin_commitment_hash: [0x21u8; 32],
                bulletin_availability_certificate_hash: [0x22u8; 32],
                bulletin_retrievability_profile_hash: [0u8; 32],
                bulletin_shard_manifest_hash: [0u8; 32],
                bulletin_custody_receipt_hash: [0u8; 32],
                bulletin_close_hash: [0x23u8; 32],
                canonical_order_certificate_hash: [0x24u8; 32],
            },
            sealing: None,
            transactions_root_hash: [0x25u8; 32],
            resulting_state_root_hash: [0x26u8; 32],
            archived_recovered_history_checkpoint_hash: [0u8; 32],
            archived_recovered_history_profile_activation_hash: [0u8; 32],
            archived_recovered_history_retention_receipt_hash: [0u8; 32],
        };
        let mut previous = previous;
        bind_canonical_collapse_continuity(&mut previous, None).expect("bind previous continuity");
        let header = BlockHeader {
            height: 2,
            view: 0,
            parent_hash: [0x27u8; 32],
            parent_state_root: StateRoot(previous.resulting_state_root_hash.to_vec()),
            state_root: StateRoot(vec![0x28u8; 32]),
            transactions_root: vec![0x29u8; 32],
            timestamp: 1,
            timestamp_ms: 1_000,
            gas_used: 0,
            validator_set: vec![vec![0x2Au8; 32]],
            producer_account_id: AccountId([0x2Bu8; 32]),
            producer_key_suite: SignatureSuite::ED25519,
            producer_pubkey_hash: [0x2Cu8; 32],
            producer_pubkey: vec![0x2Du8; 32],
            oracle_counter: 0,
            oracle_trace_hash: [0x2Eu8; 32],
            guardian_certificate: None,
            sealed_finality_proof: None,
            canonical_order_certificate: None,
            timeout_certificate: None,
            parent_qc: QuorumCertificate::default(),
            previous_canonical_collapse_commitment_hash:
                canonical_collapse_commitment_hash_from_object(&previous).unwrap(),
            canonical_collapse_extension_certificate: Some(certificate_from_predecessor(&previous)),
            publication_frontier: None,
            signature: vec![],
        };

        assert!(verify_block_header_canonical_collapse_evidence(&header, None).is_err());
    }

    #[test]
    fn block_header_canonical_collapse_evidence_rejects_parent_state_root_mismatch() {
        let previous = CanonicalCollapseObject {
            height: 1,
            previous_canonical_collapse_commitment_hash: [0u8; 32],
            continuity_accumulator_hash: [0u8; 32],
            continuity_recursive_proof: Default::default(),
            ordering: CanonicalOrderingCollapse {
                height: 6,
                kind: CanonicalCollapseKind::Close,
                bulletin_commitment_hash: [31u8; 32],
                bulletin_availability_certificate_hash: [32u8; 32],
                bulletin_retrievability_profile_hash: [0u8; 32],
                bulletin_shard_manifest_hash: [0u8; 32],
                bulletin_custody_receipt_hash: [0u8; 32],
                bulletin_close_hash: [33u8; 32],
                canonical_order_certificate_hash: [34u8; 32],
            },
            sealing: None,
            transactions_root_hash: [35u8; 32],
            resulting_state_root_hash: [36u8; 32],
            archived_recovered_history_checkpoint_hash: [0u8; 32],
            archived_recovered_history_profile_activation_hash: [0u8; 32],
            archived_recovered_history_retention_receipt_hash: [0u8; 32],
        };
        let mut previous = previous;
        bind_canonical_collapse_continuity(&mut previous, None).expect("bind previous continuity");
        let header = BlockHeader {
            height: 2,
            view: 0,
            parent_hash: [37u8; 32],
            parent_state_root: StateRoot(vec![0xFFu8; 32]),
            state_root: StateRoot(vec![38u8; 32]),
            transactions_root: vec![39u8; 32],
            timestamp: 1,
            timestamp_ms: 1_000,
            gas_used: 0,
            validator_set: vec![vec![40u8; 32]],
            producer_account_id: AccountId([41u8; 32]),
            producer_key_suite: SignatureSuite::ED25519,
            producer_pubkey_hash: [42u8; 32],
            producer_pubkey: vec![43u8; 32],
            oracle_counter: 0,
            oracle_trace_hash: [44u8; 32],
            guardian_certificate: None,
            sealed_finality_proof: None,
            canonical_order_certificate: None,
            timeout_certificate: None,
            parent_qc: QuorumCertificate::default(),
            previous_canonical_collapse_commitment_hash:
                canonical_collapse_commitment_hash_from_object(&previous).unwrap(),
            canonical_collapse_extension_certificate: Some(certificate_from_predecessor(&previous)),
            publication_frontier: None,
            signature: vec![],
        };

        assert!(verify_block_header_canonical_collapse_evidence(&header, Some(&previous)).is_err());
    }

    #[test]
    fn block_header_canonical_collapse_evidence_accepts_recursive_proof_backed_predecessor() {
        let grandparent = CanonicalCollapseObject {
            height: 1,
            previous_canonical_collapse_commitment_hash: [0u8; 32],
            continuity_accumulator_hash: [0u8; 32],
            continuity_recursive_proof: Default::default(),
            ordering: CanonicalOrderingCollapse {
                height: 1,
                kind: CanonicalCollapseKind::Close,
                bulletin_commitment_hash: [51u8; 32],
                bulletin_availability_certificate_hash: [52u8; 32],
                bulletin_retrievability_profile_hash: [0u8; 32],
                bulletin_shard_manifest_hash: [0u8; 32],
                bulletin_custody_receipt_hash: [0u8; 32],
                bulletin_close_hash: [53u8; 32],
                canonical_order_certificate_hash: [54u8; 32],
            },
            sealing: None,
            transactions_root_hash: [55u8; 32],
            resulting_state_root_hash: [56u8; 32],
            archived_recovered_history_checkpoint_hash: [0u8; 32],
            archived_recovered_history_profile_activation_hash: [0u8; 32],
            archived_recovered_history_retention_receipt_hash: [0u8; 32],
        };
        let mut grandparent = grandparent;
        bind_canonical_collapse_continuity(&mut grandparent, None)
            .expect("bind grandparent continuity");
        let previous = CanonicalCollapseObject {
            height: 2,
            previous_canonical_collapse_commitment_hash:
                canonical_collapse_commitment_hash_from_object(&grandparent).unwrap(),
            continuity_accumulator_hash: [0u8; 32],
            continuity_recursive_proof: Default::default(),
            ordering: CanonicalOrderingCollapse {
                height: 2,
                kind: CanonicalCollapseKind::Close,
                bulletin_commitment_hash: [57u8; 32],
                bulletin_availability_certificate_hash: [58u8; 32],
                bulletin_retrievability_profile_hash: [0u8; 32],
                bulletin_shard_manifest_hash: [0u8; 32],
                bulletin_custody_receipt_hash: [0u8; 32],
                bulletin_close_hash: [59u8; 32],
                canonical_order_certificate_hash: [60u8; 32],
            },
            sealing: None,
            transactions_root_hash: [61u8; 32],
            resulting_state_root_hash: [62u8; 32],
            archived_recovered_history_checkpoint_hash: [0u8; 32],
            archived_recovered_history_profile_activation_hash: [0u8; 32],
            archived_recovered_history_retention_receipt_hash: [0u8; 32],
        };
        let mut previous = previous;
        bind_canonical_collapse_continuity(&mut previous, Some(&grandparent))
            .expect("bind previous continuity");
        let header = BlockHeader {
            height: 3,
            view: 0,
            parent_hash: [63u8; 32],
            parent_state_root: StateRoot(previous.resulting_state_root_hash.to_vec()),
            state_root: StateRoot(vec![64u8; 32]),
            transactions_root: vec![65u8; 32],
            timestamp: 1,
            timestamp_ms: 1_000,
            gas_used: 0,
            validator_set: vec![vec![66u8; 32]],
            producer_account_id: AccountId([67u8; 32]),
            producer_key_suite: SignatureSuite::ED25519,
            producer_pubkey_hash: [68u8; 32],
            producer_pubkey: vec![69u8; 32],
            oracle_counter: 0,
            oracle_trace_hash: [70u8; 32],
            guardian_certificate: None,
            sealed_finality_proof: None,
            canonical_order_certificate: None,
            timeout_certificate: None,
            parent_qc: QuorumCertificate::default(),
            previous_canonical_collapse_commitment_hash:
                canonical_collapse_commitment_hash_from_object(&previous).unwrap(),
            canonical_collapse_extension_certificate: Some(certificate_from_predecessor(&previous)),
            publication_frontier: None,
            signature: vec![],
        };

        verify_block_header_canonical_collapse_evidence(&header, Some(&previous))
            .expect("extension certificate should verify");
    }

    #[test]
    fn canonical_collapse_recursive_proof_rejects_missing_predecessor_step() {
        let previous = sample_canonical_collapse_object(1, None, 0x31);
        let current = sample_canonical_collapse_object(2, Some(&previous), 0x41);
        let mut proof = current.continuity_recursive_proof.clone();
        proof.previous_canonical_collapse_commitment_hash = [0u8; 32];

        assert!(verify_canonical_collapse_recursive_proof(&proof).is_err());
    }

    #[test]
    fn canonical_collapse_recursive_proof_rejects_previous_proof_hash_mismatch() {
        let previous = sample_canonical_collapse_object(1, None, 0x51);
        let current = sample_canonical_collapse_object(2, Some(&previous), 0x61);
        let mut proof = current.continuity_recursive_proof.clone();
        proof.previous_recursive_proof_hash[0] ^= 0xFF;

        assert!(verify_canonical_collapse_recursive_proof(&proof).is_err());
    }

    #[test]
    fn canonical_collapse_recursive_proof_rejects_corrupted_proof_bytes() {
        let previous = sample_canonical_collapse_object(1, None, 0x71);
        let current = sample_canonical_collapse_object(2, Some(&previous), 0x81);
        let mut proof = current.continuity_recursive_proof.clone();
        proof.proof_bytes[0] ^= 0xFF;

        assert!(verify_canonical_collapse_recursive_proof(&proof).is_err());
    }

    #[test]
    fn canonical_collapse_recursive_proof_matches_collapse_rejects_payload_mismatch() {
        let previous = sample_canonical_collapse_object(1, None, 0x91);
        let current = sample_canonical_collapse_object(2, Some(&previous), 0xA1);
        let proof = current.continuity_recursive_proof.clone();
        let mut mismatched = current.clone();
        mismatched.ordering.bulletin_commitment_hash[0] ^= 0xFF;

        assert!(verify_canonical_collapse_recursive_proof_matches_collapse(
            &mismatched,
            &proof,
            Some(&previous),
        )
        .is_err());
    }

    #[test]
    fn canonical_collapse_recursive_proof_hash_changes_when_previous_step_changes() {
        let genesis = sample_canonical_collapse_object(1, None, 0xB1);
        let step_two = sample_canonical_collapse_object(2, Some(&genesis), 0xB2);
        let step_three = sample_canonical_collapse_object(3, Some(&step_two), 0xB3);
        let mut carried = step_three.continuity_recursive_proof.clone();
        carried.previous_recursive_proof_hash[0] ^= 0x55;

        let expected_hash =
            canonical_collapse_recursive_proof_hash(&step_three.continuity_recursive_proof)
                .expect("expected recursive proof hash");
        let tampered_hash = canonical_collapse_recursive_proof_hash(&carried)
            .expect("tampered recursive proof hash");

        assert_ne!(expected_hash, tampered_hash);
        assert!(verify_canonical_collapse_recursive_proof(&carried).is_err());
    }

    #[test]
    fn bind_canonical_collapse_continuity_can_emit_succinct_sp1_reference_proof() {
        let _guard = continuity_env_lock().lock().expect("continuity env lock");
        let previous_env = std::env::var("IOI_AFT_CONTINUITY_PROOF_SYSTEM").ok();
        std::env::set_var("IOI_AFT_CONTINUITY_PROOF_SYSTEM", "succinct-sp1-v1");

        let previous = sample_canonical_collapse_object(1, None, 0xC1);
        let current = sample_canonical_collapse_object(2, Some(&previous), 0xC2);

        assert_eq!(
            current.continuity_recursive_proof.proof_system,
            CanonicalCollapseContinuityProofSystem::SuccinctSp1V1
        );
        verify_canonical_collapse_continuity(&current, Some(&previous))
            .expect("succinct continuity proof should verify");

        if let Some(value) = previous_env {
            std::env::set_var("IOI_AFT_CONTINUITY_PROOF_SYSTEM", value);
        } else {
            std::env::remove_var("IOI_AFT_CONTINUITY_PROOF_SYSTEM");
        }
    }

    #[test]
    fn block_header_canonical_collapse_evidence_rejects_mismatched_predecessor_head() {
        let grandparent = CanonicalCollapseObject {
            height: 1,
            previous_canonical_collapse_commitment_hash: [0u8; 32],
            continuity_accumulator_hash: [0u8; 32],
            continuity_recursive_proof: Default::default(),
            ordering: CanonicalOrderingCollapse {
                height: 1,
                kind: CanonicalCollapseKind::Close,
                bulletin_commitment_hash: [71u8; 32],
                bulletin_availability_certificate_hash: [72u8; 32],
                bulletin_retrievability_profile_hash: [0u8; 32],
                bulletin_shard_manifest_hash: [0u8; 32],
                bulletin_custody_receipt_hash: [0u8; 32],
                bulletin_close_hash: [73u8; 32],
                canonical_order_certificate_hash: [74u8; 32],
            },
            sealing: None,
            transactions_root_hash: [75u8; 32],
            resulting_state_root_hash: [76u8; 32],
            archived_recovered_history_checkpoint_hash: [0u8; 32],
            archived_recovered_history_profile_activation_hash: [0u8; 32],
            archived_recovered_history_retention_receipt_hash: [0u8; 32],
        };
        let mut grandparent = grandparent;
        bind_canonical_collapse_continuity(&mut grandparent, None)
            .expect("bind grandparent continuity");
        let previous = CanonicalCollapseObject {
            height: 2,
            previous_canonical_collapse_commitment_hash:
                canonical_collapse_commitment_hash_from_object(&grandparent).unwrap(),
            continuity_accumulator_hash: [0u8; 32],
            continuity_recursive_proof: Default::default(),
            ordering: CanonicalOrderingCollapse {
                height: 2,
                kind: CanonicalCollapseKind::Close,
                bulletin_commitment_hash: [77u8; 32],
                bulletin_availability_certificate_hash: [78u8; 32],
                bulletin_retrievability_profile_hash: [0u8; 32],
                bulletin_shard_manifest_hash: [0u8; 32],
                bulletin_custody_receipt_hash: [0u8; 32],
                bulletin_close_hash: [79u8; 32],
                canonical_order_certificate_hash: [80u8; 32],
            },
            sealing: None,
            transactions_root_hash: [81u8; 32],
            resulting_state_root_hash: [82u8; 32],
            archived_recovered_history_checkpoint_hash: [0u8; 32],
            archived_recovered_history_profile_activation_hash: [0u8; 32],
            archived_recovered_history_retention_receipt_hash: [0u8; 32],
        };
        let mut previous = previous;
        bind_canonical_collapse_continuity(&mut previous, Some(&grandparent))
            .expect("bind previous continuity");
        let mut wrong_certificate = certificate_from_predecessor(&previous);
        wrong_certificate.predecessor_recursive_proof_hash[0] ^= 0xFF;

        let header = BlockHeader {
            height: 3,
            view: 0,
            parent_hash: [83u8; 32],
            parent_state_root: StateRoot(previous.resulting_state_root_hash.to_vec()),
            state_root: StateRoot(vec![84u8; 32]),
            transactions_root: vec![85u8; 32],
            timestamp: 1,
            timestamp_ms: 1_000,
            gas_used: 0,
            validator_set: vec![vec![86u8; 32]],
            producer_account_id: AccountId([87u8; 32]),
            producer_key_suite: SignatureSuite::ED25519,
            producer_pubkey_hash: [88u8; 32],
            producer_pubkey: vec![89u8; 32],
            oracle_counter: 0,
            oracle_trace_hash: [90u8; 32],
            guardian_certificate: None,
            sealed_finality_proof: None,
            canonical_order_certificate: None,
            timeout_certificate: None,
            parent_qc: QuorumCertificate::default(),
            previous_canonical_collapse_commitment_hash:
                canonical_collapse_commitment_hash_from_object(&previous).unwrap(),
            canonical_collapse_extension_certificate: Some(wrong_certificate),
            publication_frontier: None,
            signature: vec![],
        };

        assert!(verify_block_header_canonical_collapse_evidence(&header, Some(&previous)).is_err());
    }
