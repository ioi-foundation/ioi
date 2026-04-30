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
    let execution_object = derive_canonical_order_execution_object(&header, &ordered_transactions)
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

