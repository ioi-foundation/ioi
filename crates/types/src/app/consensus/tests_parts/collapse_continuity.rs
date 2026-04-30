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

    let collapse = derive_canonical_collapse_object(&header, &[]).expect("derive collapse object");
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
    let collapse = derive_canonical_collapse_object_with_previous(&header, &[], Some(&previous))
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
    let tampered_hash =
        canonical_collapse_recursive_proof_hash(&carried).expect("tampered recursive proof hash");

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
