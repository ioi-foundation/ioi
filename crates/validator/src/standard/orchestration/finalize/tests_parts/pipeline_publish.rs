#[tokio::test]
async fn publish_experimental_recovery_pipeline_enqueues_recovered_publication_bundle_after_receipts_and_reveals(
) {
    let (block, capsule, binding_assignments) = sample_block_with_sealed_recovery_bindings();
    let previous_canonical_collapse =
        sample_previous_canonical_collapse_object(block.header.height - 1, 0x74);
    let witness_seed = sample_guardian_witness_seed();
    let witness_set =
        sample_guardian_witness_set(vec![[0x91u8; 32], [0x92u8; 32], [0x93u8; 32], [0x94u8; 32]]);
    let materials = build_experimental_multi_witness_recovery_share_materials(
        &block.header,
        &block.transactions,
        &witness_seed,
        &witness_set,
        0,
        sample_parity_family_share_count(),
        sample_parity_family_recovery_threshold(),
    )
    .expect("recovery share materials");
    let signer = MockRecoveryRevealSigner {
        materials: materials
            .iter()
            .cloned()
            .map(|material| {
                (
                    (
                        material.witness_manifest_hash,
                        material.share_commitment_hash,
                    ),
                    material,
                )
            })
            .collect(),
    };

    let synthetic_recovered =
        build_recovered_publication_bundle(&materials).expect("synthetic recovered bundle");
    let (segment_start_height, segment_end_height) = archived_recovered_restart_page_range(
        synthetic_recovered.height,
        AFT_RECOVERED_CONSENSUS_HEADER_WINDOW,
        AFT_RECOVERED_CONSENSUS_HEADER_STITCH_OVERLAP,
        recovered_consensus_header_stitch_window_budget(),
        recovered_consensus_header_stitch_segment_budget(),
    )
    .expect("current archived page range");
    let (previous_start_height, previous_end_height) = archived_recovered_restart_page_range(
        segment_end_height - 1,
        AFT_RECOVERED_CONSENSUS_HEADER_WINDOW,
        AFT_RECOVERED_CONSENSUS_HEADER_STITCH_OVERLAP,
        recovered_consensus_header_stitch_window_budget(),
        recovered_consensus_header_stitch_segment_budget(),
    )
    .expect("previous archived page range");
    let archived_profile = default_archived_recovered_history_profile()
        .expect("default archived recovered-history profile");
    let archived_activation =
        build_archived_recovered_history_profile_activation(&archived_profile, None, 1, None)
            .expect("default archived recovered-history profile activation");
    let mut raw_state = BTreeMap::new();
    let synthetic_start_height = previous_start_height.min(segment_start_height);
    let synthetic_bundles = (synthetic_start_height..segment_end_height)
        .map(|height| {
            (
                height,
                synthetic_recovered_publication_bundle_for_height(&synthetic_recovered, height),
            )
        })
        .collect::<BTreeMap<_, _>>();
    for bundle in synthetic_bundles.values() {
        let recovered_key = aft_recovered_publication_bundle_key(
            bundle.height,
            &bundle.block_commitment_hash,
            &bundle.supporting_witness_manifest_hashes,
        )
        .expect("recovered publication bundle key");
        raw_state.insert(
            recovered_key,
            codec::to_bytes_canonical(bundle).expect("encode recovered publication bundle"),
        );
    }
    let previous_segment_bundles = (previous_start_height..=previous_end_height)
        .map(|height| {
            synthetic_bundles
                .get(&height)
                .cloned()
                .expect("synthetic previous-segment recovered bundle")
        })
        .collect::<Vec<_>>();
    let previous_segment = build_archived_recovered_history_segment(
        &previous_segment_bundles,
        None,
        None,
        &archived_profile,
        &archived_activation,
    )
    .expect("previous archived recovered-history segment");
    let previous_page = synthetic_archived_restart_page(
        &previous_segment,
        synthetic_recovered.parent_block_commitment_hash,
    );
    let previous_checkpoint =
        build_archived_recovered_history_checkpoint(&previous_segment, &previous_page, None)
            .expect("previous archived recovered-history checkpoint");
    let active_validator_sets = validator_sets(&[(18, 1), (145, 1), (19, 1)]);
    let active_validator_set_bytes =
        write_validator_sets(&active_validator_sets).expect("encode active validator sets");
    let persisted_active_validator_sets = read_validator_sets(&active_validator_set_bytes)
        .expect("decode persisted active validator sets");
    raw_state.insert(
        aft_archived_recovered_history_segment_key(
            previous_segment.start_height,
            previous_segment.end_height,
        ),
        codec::to_bytes_canonical(&previous_segment)
            .expect("encode previous archived recovered-history segment"),
    );
    raw_state.insert(
        aft_archived_recovered_restart_page_key(&previous_page.segment_hash),
        codec::to_bytes_canonical(&previous_page)
            .expect("encode previous archived recovered restart page"),
    );
    raw_state.insert(
        aft_archived_recovered_history_checkpoint_key(
            previous_checkpoint.covered_start_height,
            previous_checkpoint.covered_end_height,
        ),
        codec::to_bytes_canonical(&previous_checkpoint)
            .expect("encode previous archived recovered-history checkpoint"),
    );
    raw_state.insert(
        ioi_types::app::AFT_LATEST_ARCHIVED_RECOVERED_HISTORY_CHECKPOINT_KEY.to_vec(),
        codec::to_bytes_canonical(&previous_checkpoint)
            .expect("encode latest archived recovered-history checkpoint"),
    );
    raw_state.insert(VALIDATOR_SET_KEY.to_vec(), active_validator_set_bytes);

    let (consensus_kick_tx, mut consensus_kick_rx) = mpsc::unbounded_channel();
    let publisher = GuardianRegistryPublisher {
        workload_client: Arc::new(StaticStateWorkloadClient { raw_state }),
        tx_pool: Arc::new(Mempool::new()),
        consensus_kick_tx,
        nonce_manager: Arc::new(Mutex::new(BTreeMap::new())),
        local_keypair: libp2p::identity::Keypair::generate_ed25519(),
        chain_id: ChainId(1),
    };

    publish_experimental_sealed_recovery_artifacts(
        &publisher,
        &block,
        Some(&capsule),
        &binding_assignments,
    )
    .await
    .expect("sealed recovery artifacts should publish");
    let published_materials = publish_experimental_locally_held_recovery_share_materials(
        &publisher,
        &signer,
        &block,
        &witness_seed,
        &witness_set,
        0,
        &binding_assignments,
    )
    .await
    .expect("share material publication should succeed");
    let recovered =
        publish_experimental_recovered_publication_bundle(&publisher, &published_materials)
            .await
            .expect("recovered publication bundle should publish")
            .expect("recovered publication bundle object");
    let (archived_profile, archived_activation) =
        ensure_archived_recovered_history_profile(&publisher)
            .await
            .expect("archived recovered-history profile should publish");
    let archived_segment = publish_archived_recovered_history_segment(
        &publisher,
        &recovered,
        &archived_profile,
        &archived_activation,
    )
    .await
    .expect("archived recovered-history segment should publish")
    .expect("archived recovered-history segment object");
    let support_materials =
        supporting_recovery_materials_for_recovered_bundle(&recovered, &published_materials)
            .expect("supporting recovery materials");
    let (recovered_full_surface, _, recovered_close, _) =
        recover_full_canonical_order_surface_from_share_materials(&support_materials)
            .expect("recover full canonical order surface");
    let canonical_collapse_object =
        ioi_types::app::derive_canonical_collapse_object_from_recovered_surface(
            &recovered_full_surface,
            &recovered_close,
            Some(&previous_canonical_collapse),
        )
        .expect("canonical collapse object from recovered surface");
    let archived_page = publish_archived_recovered_restart_page(
        &publisher,
        &archived_segment,
        &canonical_collapse_object,
        &recovered,
        &published_materials,
    )
    .await
    .expect("archived recovered restart page should publish")
    .expect("archived recovered restart page object");
    let archived_checkpoint = publish_archived_recovered_history_checkpoint(
        &publisher,
        &archived_segment,
        &archived_page,
    )
    .await
    .expect("archived recovered-history checkpoint should publish")
    .expect("archived recovered-history checkpoint object");
    let archived_retention_receipt = publish_archived_recovered_history_retention_receipt(
        &publisher,
        &archived_checkpoint,
        &archived_profile,
    )
    .await
    .expect("archived recovered-history retention receipt should publish")
    .expect("archived recovered-history retention receipt object");

    let selected = publisher.tx_pool.select_transactions(48);
    assert_eq!(
        selected.len(),
        3 * usize::from(sample_parity_family_share_count()) + 8
    );

    let mut methods = Vec::new();
    let mut published_recovered = None;
    let mut published_archived_profile = None;
    let mut published_archived_profile_activation = None;
    let mut published_archived_segment = None;
    let mut published_archived_page = None;
    let mut published_archived_checkpoint = None;
    let mut published_archived_retention_receipt = None;
    for tx in selected {
        match tx {
            ChainTransaction::System(system_tx) => match system_tx.payload {
                SystemPayload::CallService {
                    service_id,
                    method,
                    params,
                } => {
                    assert_eq!(service_id, "guardian_registry");
                    if method == "publish_aft_recovered_publication_bundle@v1" {
                        published_recovered = Some(
                            codec::from_bytes_canonical::<RecoveredPublicationBundle>(&params)
                                .expect("decode recovered publication bundle"),
                        );
                    } else if method == "publish_aft_archived_recovered_history_profile@v1" {
                        published_archived_profile = Some(
                            codec::from_bytes_canonical::<ArchivedRecoveredHistoryProfile>(&params)
                                .expect("decode archived recovered-history profile"),
                        );
                    } else if method
                        == "publish_aft_archived_recovered_history_profile_activation@v1"
                    {
                        published_archived_profile_activation =
                            Some(
                                codec::from_bytes_canonical::<
                                    ArchivedRecoveredHistoryProfileActivation,
                                >(&params)
                                .expect("decode archived recovered-history profile activation"),
                            );
                    } else if method == "publish_aft_archived_recovered_history_segment@v1" {
                        published_archived_segment = Some(
                            codec::from_bytes_canonical::<ArchivedRecoveredHistorySegment>(&params)
                                .expect("decode archived recovered-history segment"),
                        );
                    } else if method == "publish_aft_archived_recovered_restart_page@v1" {
                        published_archived_page = Some(
                            codec::from_bytes_canonical::<ArchivedRecoveredRestartPage>(&params)
                                .expect("decode archived recovered restart page"),
                        );
                    } else if method == "publish_aft_archived_recovered_history_checkpoint@v1" {
                        published_archived_checkpoint = Some(
                            codec::from_bytes_canonical::<ArchivedRecoveredHistoryCheckpoint>(
                                &params,
                            )
                            .expect("decode archived recovered-history checkpoint"),
                        );
                    } else if method
                        == "publish_aft_archived_recovered_history_retention_receipt@v1"
                    {
                        published_archived_retention_receipt =
                            Some(
                                codec::from_bytes_canonical::<
                                    ArchivedRecoveredHistoryRetentionReceipt,
                                >(&params)
                                .expect("decode archived recovered-history retention receipt"),
                            );
                    }
                    methods.push(method);
                }
            },
            other => panic!("unexpected non-system publication tx: {other:?}"),
        }
    }

    assert_eq!(
        methods,
        vec![
            "publish_aft_recovery_capsule@v1".to_string(),
            "publish_aft_recovery_witness_certificate@v1".to_string(),
            "publish_aft_recovery_share_receipt@v1".to_string(),
            "publish_aft_recovery_witness_certificate@v1".to_string(),
            "publish_aft_recovery_share_receipt@v1".to_string(),
            "publish_aft_recovery_witness_certificate@v1".to_string(),
            "publish_aft_recovery_share_receipt@v1".to_string(),
            "publish_aft_recovery_witness_certificate@v1".to_string(),
            "publish_aft_recovery_share_receipt@v1".to_string(),
            "publish_aft_recovery_share_material@v1".to_string(),
            "publish_aft_recovery_share_material@v1".to_string(),
            "publish_aft_recovery_share_material@v1".to_string(),
            "publish_aft_recovery_share_material@v1".to_string(),
            "publish_aft_recovered_publication_bundle@v1".to_string(),
            "publish_aft_archived_recovered_history_profile@v1".to_string(),
            "publish_aft_archived_recovered_history_profile_activation@v1".to_string(),
            "publish_aft_archived_recovered_history_segment@v1".to_string(),
            "publish_aft_archived_recovered_restart_page@v1".to_string(),
            "publish_aft_archived_recovered_history_checkpoint@v1".to_string(),
            "publish_aft_archived_recovered_history_retention_receipt@v1".to_string(),
        ]
    );
    assert_eq!(published_recovered, Some(recovered.clone()));
    assert_eq!(published_archived_profile, Some(archived_profile.clone()));
    assert_eq!(
        published_archived_profile_activation,
        Some(
            build_archived_recovered_history_profile_activation(&archived_profile, None, 1, None,)
                .expect("expected archived recovered-history profile activation")
        )
    );
    assert_eq!(published_archived_segment, Some(archived_segment.clone()));
    assert_eq!(published_archived_page, Some(archived_page.clone()));
    assert_eq!(
        published_archived_checkpoint,
        Some(archived_checkpoint.clone())
    );
    assert_eq!(
        published_archived_retention_receipt,
        Some(archived_retention_receipt.clone())
    );
    assert_eq!(
        recovered,
        build_recovered_publication_bundle(&materials).expect("expected recovered bundle")
    );
    let expected_archived_bundles = (segment_start_height..=segment_end_height)
        .map(|height| {
            if height == recovered.height {
                recovered.clone()
            } else {
                synthetic_bundles
                    .get(&height)
                    .cloned()
                    .expect("synthetic archived recovered-history bundle")
            }
        })
        .collect::<Vec<_>>();
    let expected_overlap_range = Some((
        segment_start_height.max(previous_segment.start_height),
        segment_end_height
            .saturating_sub(1)
            .min(previous_segment.end_height),
    ));
    assert_eq!(
        archived_segment,
        build_archived_recovered_history_segment(
            &expected_archived_bundles,
            Some(&previous_segment),
            expected_overlap_range,
            &archived_profile,
            &archived_activation,
        )
        .expect("expected archived recovered-history segment")
    );
    let expected_archived_page = build_archived_recovered_restart_page(
        &archived_segment,
        &[
            previous_page.restart_headers[usize::try_from(
                segment_start_height - previous_start_height,
            )
            .expect("overlap page offset")..]
                .to_vec(),
            vec![archived_page
                .restart_headers
                .last()
                .cloned()
                .expect("published archived restart page tip")],
        ]
        .concat(),
    )
    .expect("expected archived recovered restart page");
    assert_eq!(archived_page, expected_archived_page);
    let expected_archived_checkpoint = build_archived_recovered_history_checkpoint(
        &archived_segment,
        &archived_page,
        Some(&previous_checkpoint),
    )
    .expect("expected archived recovered-history checkpoint");
    assert_eq!(archived_checkpoint, expected_archived_checkpoint);
    let expected_archived_retention_receipt = build_archived_recovered_history_retention_receipt(
        &archived_checkpoint,
        canonical_validator_sets_hash(&persisted_active_validator_sets)
            .expect("validator set commitment hash"),
        archived_recovered_history_retained_through_height(&archived_checkpoint, &archived_profile)
            .expect("retained-through height from archived profile"),
    )
    .expect("expected archived recovered-history retention receipt");
    assert_eq!(
        archived_retention_receipt,
        expected_archived_retention_receipt
    );

    for _ in 0..(3 * usize::from(sample_parity_family_share_count()) + 8) {
        consensus_kick_rx
            .try_recv()
            .expect("publication should kick consensus for each enqueued tx");
    }
    assert!(consensus_kick_rx.try_recv().is_err());
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
    let ordered_transactions =
        ioi_types::app::canonicalize_transactions_for_header(&base_header, &[tx_one, tx_two])
            .expect("canonicalized transactions");
    let tx_hashes: Vec<[u8; 32]> = ordered_transactions
        .iter()
        .map(|tx| tx.hash().expect("tx hash"))
        .collect();

    let mut header = base_header;
    header.transactions_root = ioi_types::app::canonical_transaction_root_from_hashes(&tx_hashes)
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
                    service_id, method, ..
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
