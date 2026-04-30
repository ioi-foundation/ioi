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
    let (header, ordered_transactions, _) = sample_committed_surface_ordering_fixture(29, 3, 24);
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
    let frontier = build_publication_frontier(&header, Some(&previous_frontier)).expect("frontier");
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
    let material_hash =
        canonical_recovery_share_material_hash(&material).expect("recovery share material hash");
    let envelope_hash = canonical_assigned_recovery_share_envelope_hash(&envelope)
        .expect("assigned recovery share envelope hash");
    let missing_hash = canonical_missing_recovery_share_hash(&missing).expect("missing share hash");
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

