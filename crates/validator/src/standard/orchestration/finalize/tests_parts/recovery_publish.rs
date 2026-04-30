#[tokio::test]
async fn publish_experimental_recovery_artifacts_enqueues_capsule_then_witness_certificate_when_capsule_is_missing(
) {
    let (block, scaffold) = sample_block_with_recovery_scaffold();
    let expected_receipt = build_experimental_recovery_scaffold_share_receipt(
        &block.header,
        &derive_recovery_witness_certificate_for_header(
            &block.header,
            block
                .header
                .guardian_certificate
                .as_ref()
                .expect("guardian certificate"),
        )
        .expect("derive recovery witness certificate")
        .expect("recovery witness certificate"),
    )
    .expect("build recovery receipt");
    let (consensus_kick_tx, mut consensus_kick_rx) = mpsc::unbounded_channel();
    let publisher = GuardianRegistryPublisher {
        workload_client: Arc::new(StaticStateWorkloadClient::default()),
        tx_pool: Arc::new(Mempool::new()),
        consensus_kick_tx,
        nonce_manager: Arc::new(Mutex::new(BTreeMap::new())),
        local_keypair: libp2p::identity::Keypair::generate_ed25519(),
        chain_id: ChainId(1),
    };

    publish_experimental_recovery_artifacts(&publisher, &block)
        .await
        .expect("recovery publication should succeed");

    let selected = publisher.tx_pool.select_transactions(8);
    assert_eq!(selected.len(), 3);

    let mut methods = Vec::new();
    let mut published_receipt = None;
    for tx in selected {
        match tx {
            ChainTransaction::System(system_tx) => match system_tx.payload {
                SystemPayload::CallService {
                    service_id,
                    method,
                    params,
                } => {
                    assert_eq!(service_id, "guardian_registry");
                    if method == "publish_aft_recovery_share_receipt@v1" {
                        published_receipt = Some(
                            codec::from_bytes_canonical::<RecoveryShareReceipt>(&params)
                                .expect("decode recovery share receipt"),
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
        ]
    );
    assert_eq!(published_receipt, Some(expected_receipt));
    for _ in 0..3 {
        consensus_kick_rx
            .try_recv()
            .expect("recovery publication should kick consensus");
    }
    assert!(consensus_kick_rx.try_recv().is_err());
    assert_eq!(scaffold.capsule.coding.recovery_threshold, 1);
}

#[tokio::test]
async fn publish_experimental_recovery_artifacts_enqueues_only_witness_certificate_and_receipt_when_capsule_matches(
) {
    let (block, scaffold) = sample_block_with_recovery_scaffold();
    let expected_receipt = build_experimental_recovery_scaffold_share_receipt(
        &block.header,
        &derive_recovery_witness_certificate_for_header(
            &block.header,
            block
                .header
                .guardian_certificate
                .as_ref()
                .expect("guardian certificate"),
        )
        .expect("derive recovery witness certificate")
        .expect("recovery witness certificate"),
    )
    .expect("build recovery receipt");
    let mut raw_state = BTreeMap::new();
    raw_state.insert(
        aft_recovery_capsule_key(block.header.height),
        codec::to_bytes_canonical(&scaffold.capsule).expect("encode recovery capsule"),
    );
    let (consensus_kick_tx, mut consensus_kick_rx) = mpsc::unbounded_channel();
    let publisher = GuardianRegistryPublisher {
        workload_client: Arc::new(StaticStateWorkloadClient { raw_state }),
        tx_pool: Arc::new(Mempool::new()),
        consensus_kick_tx,
        nonce_manager: Arc::new(Mutex::new(BTreeMap::new())),
        local_keypair: libp2p::identity::Keypair::generate_ed25519(),
        chain_id: ChainId(1),
    };

    publish_experimental_recovery_artifacts(&publisher, &block)
        .await
        .expect("recovery publication should succeed");

    let selected = publisher.tx_pool.select_transactions(8);
    assert_eq!(selected.len(), 2);

    let mut methods = Vec::new();
    let mut published_receipt = None;
    for tx in selected {
        match tx {
            ChainTransaction::System(system_tx) => match system_tx.payload {
                SystemPayload::CallService {
                    service_id,
                    method,
                    params,
                } => {
                    assert_eq!(service_id, "guardian_registry");
                    if method == "publish_aft_recovery_share_receipt@v1" {
                        published_receipt = Some(
                            codec::from_bytes_canonical::<RecoveryShareReceipt>(&params)
                                .expect("decode recovery share receipt"),
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
            "publish_aft_recovery_witness_certificate@v1".to_string(),
            "publish_aft_recovery_share_receipt@v1".to_string(),
        ]
    );
    assert_eq!(published_receipt, Some(expected_receipt));
    for _ in 0..2 {
        consensus_kick_rx
            .try_recv()
            .expect("recovery publication should kick consensus");
    }
    assert!(consensus_kick_rx.try_recv().is_err());
}

#[tokio::test]
async fn publish_experimental_recovery_artifacts_skips_receipt_when_missing_share_exists() {
    let (block, scaffold) = sample_block_with_recovery_scaffold();
    let mut raw_state = BTreeMap::new();
    raw_state.insert(
        aft_recovery_capsule_key(block.header.height),
        codec::to_bytes_canonical(&scaffold.capsule).expect("encode recovery capsule"),
    );
    raw_state.insert(
        aft_missing_recovery_share_key(block.header.height, &[0x41u8; 32]),
        codec::to_bytes_canonical(&ioi_types::app::MissingRecoveryShare {
            height: block.header.height,
            witness_manifest_hash: [0x41u8; 32],
            recovery_capsule_hash: scaffold
                .recovery_binding()
                .expect("recovery binding")
                .recovery_capsule_hash,
            recovery_window_close_ms: scaffold.capsule.recovery_window_close_ms,
        })
        .expect("encode missing share"),
    );
    let (consensus_kick_tx, mut consensus_kick_rx) = mpsc::unbounded_channel();
    let publisher = GuardianRegistryPublisher {
        workload_client: Arc::new(StaticStateWorkloadClient { raw_state }),
        tx_pool: Arc::new(Mempool::new()),
        consensus_kick_tx,
        nonce_manager: Arc::new(Mutex::new(BTreeMap::new())),
        local_keypair: libp2p::identity::Keypair::generate_ed25519(),
        chain_id: ChainId(1),
    };

    publish_experimental_recovery_artifacts(&publisher, &block)
        .await
        .expect("recovery publication should succeed");

    let methods = publisher
        .tx_pool
        .select_transactions(8)
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
        vec!["publish_aft_recovery_witness_certificate@v1".to_string()]
    );
    consensus_kick_rx
        .try_recv()
        .expect("recovery publication should kick consensus");
    assert!(consensus_kick_rx.try_recv().is_err());
}

#[tokio::test]
async fn publish_experimental_recovery_artifacts_enqueues_only_witness_certificate_when_capsule_matches(
) {
    let (block, scaffold) = sample_block_with_recovery_scaffold();
    let mut raw_state = BTreeMap::new();
    raw_state.insert(
        aft_recovery_capsule_key(block.header.height),
        codec::to_bytes_canonical(&scaffold.capsule).expect("encode recovery capsule"),
    );
    raw_state.insert(
        aft_recovery_share_receipt_key(
            block.header.height,
            &[0x41u8; 32],
            &canonical_block_commitment_hash(&block.header).expect("block commitment"),
        ),
        codec::to_bytes_canonical(
            &build_experimental_recovery_scaffold_share_receipt(
                &block.header,
                &derive_recovery_witness_certificate_for_header(
                    &block.header,
                    block
                        .header
                        .guardian_certificate
                        .as_ref()
                        .expect("guardian certificate"),
                )
                .expect("derive recovery witness certificate")
                .expect("recovery witness certificate"),
            )
            .expect("build recovery receipt"),
        )
        .expect("encode recovery receipt"),
    );
    let (consensus_kick_tx, mut consensus_kick_rx) = mpsc::unbounded_channel();
    let publisher = GuardianRegistryPublisher {
        workload_client: Arc::new(StaticStateWorkloadClient { raw_state }),
        tx_pool: Arc::new(Mempool::new()),
        consensus_kick_tx,
        nonce_manager: Arc::new(Mutex::new(BTreeMap::new())),
        local_keypair: libp2p::identity::Keypair::generate_ed25519(),
        chain_id: ChainId(1),
    };

    publish_experimental_recovery_artifacts(&publisher, &block)
        .await
        .expect("recovery publication should succeed");

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
        vec!["publish_aft_recovery_witness_certificate@v1".to_string()]
    );
    consensus_kick_rx
        .try_recv()
        .expect("recovery publication should kick consensus");
    assert!(consensus_kick_rx.try_recv().is_err());
}

#[tokio::test]
async fn publish_experimental_recovery_artifacts_skips_when_capsule_is_mismatched() {
    let (block, scaffold) = sample_block_with_recovery_scaffold();
    let mismatched_capsule = RecoveryCapsule {
        payload_commitment_hash: [0x55u8; 32],
        ..scaffold.capsule
    };
    let mut raw_state = BTreeMap::new();
    raw_state.insert(
        aft_recovery_capsule_key(block.header.height),
        codec::to_bytes_canonical(&mismatched_capsule).expect("encode recovery capsule"),
    );
    let (consensus_kick_tx, mut consensus_kick_rx) = mpsc::unbounded_channel();
    let publisher = GuardianRegistryPublisher {
        workload_client: Arc::new(StaticStateWorkloadClient { raw_state }),
        tx_pool: Arc::new(Mempool::new()),
        consensus_kick_tx,
        nonce_manager: Arc::new(Mutex::new(BTreeMap::new())),
        local_keypair: libp2p::identity::Keypair::generate_ed25519(),
        chain_id: ChainId(1),
    };

    publish_experimental_recovery_artifacts(&publisher, &block)
        .await
        .expect("mismatched capsule should be skipped, not rejected");

    assert!(
            publisher.tx_pool.select_transactions(8).is_empty(),
            "no publication tx should be enqueued when the published capsule mismatches the signed binding"
        );
    assert!(
        consensus_kick_rx.try_recv().is_err(),
        "skipped recovery publication should not kick consensus"
    );
}

#[tokio::test]
async fn publish_experimental_sealed_recovery_artifacts_enqueues_capsule_witness_certificates_and_receipts(
) {
    let (block, capsule, binding_assignments) = sample_block_with_sealed_recovery_bindings();
    let expected_witnesses = binding_assignments
        .iter()
        .map(|assignment| assignment.witness_manifest_hash)
        .collect::<std::collections::BTreeSet<_>>();
    let expected_receipts = block
        .header
        .sealed_finality_proof
        .as_ref()
        .expect("sealed finality proof")
        .witness_certificates
        .iter()
        .map(|witness_certificate| {
            let statement =
                ioi_types::app::guardian_witness_statement_for_header_with_recovery_binding(
                    &block.header,
                    block
                        .header
                        .guardian_certificate
                        .as_ref()
                        .expect("guardian certificate"),
                    witness_certificate.recovery_binding.clone(),
                );
            let certificate = ioi_types::app::derive_recovery_witness_certificate(
                &statement,
                witness_certificate,
            )
            .expect("derive sealed recovery witness certificate")
            .expect("recovery witness certificate");
            build_recovery_share_receipt_for_header(&block.header, &certificate)
                .expect("build recovery share receipt")
        })
        .collect::<Vec<_>>();
    let (consensus_kick_tx, mut consensus_kick_rx) = mpsc::unbounded_channel();
    let publisher = GuardianRegistryPublisher {
        workload_client: Arc::new(StaticStateWorkloadClient::default()),
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
    .expect("sealed recovery publication should succeed");

    let selected = publisher.tx_pool.select_transactions(16);
    assert_eq!(
        selected.len(),
        1 + 2 * usize::from(sample_parity_family_share_count())
    );

    let mut methods = Vec::new();
    let mut published_receipts = Vec::new();
    let mut published_witnesses = std::collections::BTreeSet::new();
    for tx in selected {
        match tx {
            ChainTransaction::System(system_tx) => match system_tx.payload {
                SystemPayload::CallService {
                    service_id,
                    method,
                    params,
                } => {
                    assert_eq!(service_id, "guardian_registry");
                    if method == "publish_aft_recovery_witness_certificate@v1" {
                        let certificate = codec::from_bytes_canonical::<
                            ioi_types::app::RecoveryWitnessCertificate,
                        >(&params)
                        .expect("decode recovery witness certificate");
                        published_witnesses.insert(certificate.witness_manifest_hash);
                    }
                    if method == "publish_aft_recovery_share_receipt@v1" {
                        published_receipts.push(
                            codec::from_bytes_canonical::<RecoveryShareReceipt>(&params)
                                .expect("decode recovery share receipt"),
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
        ]
    );
    assert_eq!(published_witnesses, expected_witnesses);
    assert_eq!(published_receipts, expected_receipts);
    for _ in 0..(1 + 2 * usize::from(sample_parity_family_share_count())) {
        consensus_kick_rx
            .try_recv()
            .expect("sealed recovery publication should kick consensus");
    }
    assert!(consensus_kick_rx.try_recv().is_err());
}

#[tokio::test]
async fn publish_experimental_sealed_recovery_artifacts_skips_when_a_witness_binding_is_tampered() {
    let (mut block, capsule, binding_assignments) = sample_block_with_sealed_recovery_bindings();
    block
        .header
        .sealed_finality_proof
        .as_mut()
        .expect("sealed finality proof")
        .witness_certificates[0]
        .recovery_binding
        .as_mut()
        .expect("recovery binding")
        .share_commitment_hash[0] ^= 0xff;
    let (consensus_kick_tx, mut consensus_kick_rx) = mpsc::unbounded_channel();
    let publisher = GuardianRegistryPublisher {
        workload_client: Arc::new(StaticStateWorkloadClient::default()),
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
    .expect("tampered sealed recovery publication should be skipped, not rejected");

    assert!(
        publisher.tx_pool.select_transactions(16).is_empty(),
        "no publication tx should be enqueued when one sealed witness binding is tampered"
    );
    assert!(
        consensus_kick_rx.try_recv().is_err(),
        "skipped sealed recovery publication should not kick consensus"
    );
}

#[tokio::test]
async fn publish_experimental_locally_held_recovery_share_materials_enqueues_public_reveals_that_reconstruct_payload(
) {
    let (block, capsule, binding_assignments) = sample_block_with_sealed_recovery_bindings();
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

    let mut raw_state = BTreeMap::new();
    raw_state.insert(
        aft_recovery_capsule_key(block.header.height),
        codec::to_bytes_canonical(&capsule).expect("encode recovery capsule"),
    );
    for witness_certificate in &block
        .header
        .sealed_finality_proof
        .as_ref()
        .expect("sealed finality proof")
        .witness_certificates
    {
        let statement = ioi_types::app::guardian_witness_statement_for_header_with_recovery_binding(
            &block.header,
            block
                .header
                .guardian_certificate
                .as_ref()
                .expect("guardian certificate"),
            witness_certificate.recovery_binding.clone(),
        );
        let certificate =
            ioi_types::app::derive_recovery_witness_certificate(&statement, witness_certificate)
                .expect("derive recovery witness certificate")
                .expect("recovery witness certificate");
        let receipt = build_recovery_share_receipt_for_header(&block.header, &certificate)
            .expect("recovery share receipt");
        raw_state.insert(
            ioi_types::app::aft_recovery_witness_certificate_key(
                certificate.height,
                &certificate.witness_manifest_hash,
            ),
            codec::to_bytes_canonical(&certificate).expect("encode recovery witness"),
        );
        raw_state.insert(
            aft_recovery_share_receipt_key(
                receipt.height,
                &receipt.witness_manifest_hash,
                &receipt.block_commitment_hash,
            ),
            codec::to_bytes_canonical(&receipt).expect("encode recovery share receipt"),
        );
    }

    let (consensus_kick_tx, mut consensus_kick_rx) = mpsc::unbounded_channel();
    let publisher = GuardianRegistryPublisher {
        workload_client: Arc::new(StaticStateWorkloadClient { raw_state }),
        tx_pool: Arc::new(Mempool::new()),
        consensus_kick_tx,
        nonce_manager: Arc::new(Mutex::new(BTreeMap::new())),
        local_keypair: libp2p::identity::Keypair::generate_ed25519(),
        chain_id: ChainId(1),
    };

    let loaded_materials = publish_experimental_locally_held_recovery_share_materials(
        &publisher,
        &signer,
        &block,
        &witness_seed,
        &witness_set,
        0,
        &binding_assignments,
    )
    .await
    .expect("recovery share material publication should succeed");
    assert_eq!(loaded_materials, materials);

    let selected = publisher.tx_pool.select_transactions(16);
    assert_eq!(
        selected.len(),
        usize::from(sample_parity_family_share_count())
    );

    let mut methods = Vec::new();
    let mut published_materials = Vec::new();
    for tx in selected {
        match tx {
            ChainTransaction::System(system_tx) => match system_tx.payload {
                SystemPayload::CallService {
                    service_id,
                    method,
                    params,
                } => {
                    assert_eq!(service_id, "guardian_registry");
                    if method == "publish_aft_recovery_share_material@v1" {
                        published_materials.push(
                            codec::from_bytes_canonical::<RecoveryShareMaterial>(&params)
                                .expect("decode recovery share material"),
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
            "publish_aft_recovery_share_material@v1".to_string(),
            "publish_aft_recovery_share_material@v1".to_string(),
            "publish_aft_recovery_share_material@v1".to_string(),
            "publish_aft_recovery_share_material@v1".to_string(),
        ]
    );
    assert_eq!(published_materials, materials);

    let reconstructed =
        recover_recoverable_slot_payload_v3_from_share_materials(&published_materials[..3])
            .expect("payload should reconstruct from three published parity-family share reveals");
    let expected_certificate =
        build_committed_surface_canonical_order_certificate(&block.header, &block.transactions)
            .expect("canonical order certificate");
    let expected_payload = build_recoverable_slot_payload_v3(
        &block.header,
        &block.transactions,
        &expected_certificate,
    )
    .expect("recoverable slot payload");
    assert_eq!(reconstructed, expected_payload);

    for _ in 0..usize::from(sample_parity_family_share_count()) {
        consensus_kick_rx
            .try_recv()
            .expect("share-material publication should kick consensus");
    }
    assert!(consensus_kick_rx.try_recv().is_err());
}

