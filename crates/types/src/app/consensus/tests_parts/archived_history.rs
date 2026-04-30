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

    let checkpoint =
        build_archived_recovered_history_checkpoint(&segment, &page, Some(&previous_checkpoint))
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
        canonical_archived_recovered_history_checkpoint_hash(&checkpoint).expect("checkpoint hash")
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

    let error = build_archived_recovered_history_retention_receipt(&checkpoint, [182u8; 32], 92)
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
    let (payload_v4, bundle, bulletin_close) = build_sample_recoverable_slot_payload_v4(22, 10, 47);
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
    let decoded_availability: BulletinAvailabilityCertificate =
        codec::from_bytes_canonical(&payload_v5.canonical_bulletin_availability_certificate_bytes)
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
    let (payload_v5, _, bulletin_close, _) = build_sample_recoverable_slot_payload_v5(2, 10, 47);
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

