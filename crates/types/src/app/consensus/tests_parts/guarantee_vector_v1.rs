#[test]
fn every_legacy_profile_has_a_valid_fail_closed_v1_vector() {
    for profile in CertificateProfile::ALL {
        let vector = guarantee_vector_of(profile);
        vector.validate().expect("legacy profile vector validates");
        assert_eq!(vector.schema_version, GuaranteeVectorVersion::V1);
        assert_eq!(vector.certificate_profiles, BTreeSet::from([profile]));
        assert!(
            !vector.crypto.end_to_end_pq,
            "{profile:?}: legacy profile cannot claim a complete PQ path"
        );
    }
}

#[test]
fn legacy_guardian_profiles_do_not_claim_target_quorum_intersection_bft() {
    for profile in [
        CertificateProfile::LiveQuorumCert,
        CertificateProfile::GuardianCommitteeCert,
    ] {
        let vector = guarantee_vector_of(profile);
        assert_eq!(vector.safety.model, SafetyModelV1::LegacyGuardianMajority);
        assert_ne!(vector.safety.model, SafetyModelV1::QuorumIntersectionBft);
        assert_eq!(vector.theorem_ids, BTreeSet::from(["T4a".to_string()]));
    }

    let seal = guarantee_vector_of(CertificateProfile::UnanimousBoundaryClose);
    assert_eq!(seal.safety.model, SafetyModelV1::UnanimousAllButOne);
    assert_eq!(
        seal.theorem_ids,
        BTreeSet::from(["T1".to_string(), "T7".to_string()])
    );
}

#[test]
fn canonical_vector_bytes_and_commitment_do_not_depend_on_set_insertion_order() {
    let mut first = guarantee_vector_of(CertificateProfile::HashPcdReference);
    first.theorem_ids.insert("T6".into());
    first.theorem_ids.insert("L-M".into());
    first.constituent_hashes.insert([2; 32]);
    first.constituent_hashes.insert([1; 32]);

    let mut second = guarantee_vector_of(CertificateProfile::HashPcdReference);
    second.theorem_ids.insert("L-M".into());
    second.theorem_ids.insert("T6".into());
    second.constituent_hashes.insert([1; 32]);
    second.constituent_hashes.insert([2; 32]);

    assert_eq!(first.canonical_bytes().unwrap(), second.canonical_bytes().unwrap());
    assert_eq!(first.commitment().unwrap(), second.commitment().unwrap());
}

#[test]
fn invalid_pq_amplification_and_at_most_once_laundering_fail_closed() {
    let mut vector = guarantee_vector_of(CertificateProfile::HashPcdReference);
    vector.crypto.end_to_end_pq = true;
    assert_eq!(
        vector.validate(),
        Err(GuaranteeVectorError::InvalidEndToEndPq)
    );

    let mut vector = guarantee_vector_of(CertificateProfile::HashPcdReference);
    vector.externalization.at_most_once = true;
    assert_eq!(
        vector.validate(),
        Err(GuaranteeVectorError::InvalidAtMostOnce)
    );

    let mut vector = guarantee_vector_of(CertificateProfile::HashPcdReference);
    vector.externalization.mode = ExternalizationModeV1::IdempotencyRegister;
    vector.externalization.at_most_once = true;
    assert_eq!(
        vector.validate(),
        Err(GuaranteeVectorError::MissingAtMostOnceProfile)
    );
}

#[test]
fn partial_bft_geometry_and_incomplete_pq_census_fail_closed() {
    let mut vector = guarantee_vector_of(CertificateProfile::HashPcdReference);
    vector.safety.committee_n = Some(4);
    assert_eq!(
        vector.validate(),
        Err(GuaranteeVectorError::IncompleteBftCoordinates)
    );

    let mut vector = guarantee_vector_of(CertificateProfile::HashPcdReference);
    vector.safety.model = SafetyModelV1::QuorumIntersectionBft;
    assert_eq!(
        vector.validate(),
        Err(GuaranteeVectorError::MissingBftCoordinates)
    );

    let mut vector = guarantee_vector_of(CertificateProfile::HashPcdReference);
    vector.safety.model = SafetyModelV1::QuorumIntersectionBft;
    vector.safety.committee_n = Some(5);
    vector.safety.fault_bound_f = Some(1);
    vector.safety.quorum_q = Some(3);
    assert_eq!(
        vector.validate(),
        Err(GuaranteeVectorError::InvalidBftCoordinates),
        "a 3-of-5 quorum intersects in only one member and is not safe for f=1"
    );

    vector.safety.committee_n = Some(4);
    vector.safety.quorum_q = Some(3);
    vector.validate().expect("3-of-4 establishes f=1 intersection");

    let mut seal = guarantee_vector_of(CertificateProfile::PqUnanimousBoundaryClose);
    seal.safety.committee_n = Some(4);
    seal.safety.fault_bound_f = Some(3);
    seal.safety.quorum_q = Some(4);
    seal.validate()
        .expect("4-of-4 seal represents conflict safety with any one honest signer");
    seal.safety.quorum_q = Some(3);
    assert_eq!(
        seal.validate(),
        Err(GuaranteeVectorError::InvalidBftCoordinates),
        "a terminal all-but-one claim cannot be relabelled from a non-unanimous certificate"
    );

    let mut vector = guarantee_vector_of(CertificateProfile::HashPcdReference);
    vector.crypto.consensus_pq = true;
    vector.crypto.channel_pq = true;
    vector.crypto.externalization_pq = true;
    vector.crypto.end_to_end_pq = true;
    assert_eq!(
        vector.validate(),
        Err(GuaranteeVectorError::InvalidPqPrimitiveCensus)
    );
}

#[test]
fn pq_requires_committed_pq_constituents_and_unknown_transforms_refuse() {
    let mut vector = guarantee_vector_of(CertificateProfile::HashPcdReference);
    vector.crypto.consensus_pq = true;
    vector.crypto.channel_pq = true;
    vector.crypto.externalization_pq = true;
    vector.crypto.end_to_end_pq = true;
    vector.crypto.primitive_suites = BTreeSet::from([
        PrimitiveSuiteV1::Sha256,
        PrimitiveSuiteV1::PqAuthenticatedChannel,
    ]);
    assert_eq!(
        vector.validate(),
        Err(GuaranteeVectorError::MissingPqConstituents),
        "an evidence-only hash binding is not a PQ consensus path"
    );

    let mut vector = guarantee_vector_of(CertificateProfile::UnanimousBoundaryClose);
    vector.crypto.consensus_pq = true;
    vector.crypto.channel_pq = true;
    vector.crypto.externalization_pq = true;
    vector.crypto.end_to_end_pq = true;
    vector.crypto.primitive_suites = BTreeSet::from([
        PrimitiveSuiteV1::HashBasedSignature,
        PrimitiveSuiteV1::PqAuthenticatedChannel,
    ]);
    vector.constituent_hashes.insert([1; 32]);
    assert_eq!(
        vector.validate(),
        Err(GuaranteeVectorError::NonPqCertificateProfile),
        "a PQ wrapper cannot relabel the legacy Ed25519 seal profile"
    );

    let mut vector = guarantee_vector_of(CertificateProfile::HashPcdReference);
    vector.transformation_hashes.insert([9; 32]);
    assert_eq!(
        vector.validate(),
        Err(GuaranteeVectorError::UnsupportedTransformation)
    );
}

#[test]
fn evidence_meet_and_policy_join_are_distinct_operations() {
    let hash = guarantee_vector_of(CertificateProfile::HashPcdReference);
    let seal = guarantee_vector_of(CertificateProfile::UnanimousBoundaryClose);
    let achieved = GuaranteeVectorV1::evidence_meet(&[hash, seal]).unwrap();
    assert_eq!(
        achieved.safety.finality_rank,
        Some(GuaranteeRank::SealedAllButOne)
    );
    assert!(!achieved.crypto.end_to_end_pq);

    let pq_policy = GuaranteeRequirementsV1 {
        minimum_finality_rank: Some(GuaranteeRank::SealedAllButOne),
        require_end_to_end_pq: true,
        ..Default::default()
    };
    let externalization_policy = GuaranteeRequirementsV1 {
        minimum_externalization: Some(ExternalizationModeV1::IdempotencyRegister),
        require_at_most_once: true,
        ..Default::default()
    };
    let joined = pq_policy.join(&externalization_policy).unwrap();
    assert!(joined.require_end_to_end_pq);
    assert!(joined.require_at_most_once);
    let verified = CertificateOnlyGuaranteeVerifierV1::verify(&[achieved]).unwrap();
    assert!(!joined.is_satisfied_by(&verified));
}

#[test]
fn exact_policy_scope_conflicts_are_typed_refusals() {
    let first = GuaranteeRequirementsV1 {
        configuration_hash: Some([1; 32]),
        ..Default::default()
    };
    let second = GuaranteeRequirementsV1 {
        configuration_hash: Some([2; 32]),
        ..Default::default()
    };
    assert_eq!(
        first.join(&second),
        Err(GuaranteeVectorError::IncompatibleRequirement(
            "configuration_hash"
        ))
    );
}

#[test]
fn certificate_only_policy_consumes_only_a_recomputed_opaque_meet() {
    let order = guarantee_vector_of(CertificateProfile::LiveQuorumCert);
    let seal = guarantee_vector_of(CertificateProfile::UnanimousBoundaryClose);
    let constituents = [order, seal];
    let verified = CertificateOnlyGuaranteeVerifierV1::verify(&constituents).unwrap();
    let exact = verified.achieved().clone();
    assert!(CertificateOnlyGuaranteeVerifierV1::verify_claim(
        &constituents,
        &exact,
        &[]
    )
    .is_ok());

    let mut wrapper_claim = exact;
    wrapper_claim.crypto.consensus_pq = true;
    assert_eq!(
        CertificateOnlyGuaranteeVerifierV1::verify_claim(
            &constituents,
            &wrapper_claim,
            &[]
        ),
        Err(GuaranteeVectorError::ClaimDiffersFromVerifiedMeet)
    );
}

#[test]
fn pq_seal_cannot_launder_bls_ordering_into_pq_consensus() {
    let mut pq_seal = guarantee_vector_of(CertificateProfile::UnanimousBoundaryClose);
    pq_seal.crypto.consensus_pq = true;
    pq_seal.crypto.primitive_suites =
        BTreeSet::from([PrimitiveSuiteV1::Sha256, PrimitiveSuiteV1::HashBasedSignature]);
    pq_seal.validate().unwrap();
    let bls_order = guarantee_vector_of(CertificateProfile::LiveQuorumCert);

    let verified = CertificateOnlyGuaranteeVerifierV1::verify(&[pq_seal, bls_order]).unwrap();
    assert!(!verified.achieved().crypto.consensus_pq);
    assert!(!GuaranteeRequirementsV1 {
        require_consensus_pq: true,
        ..Default::default()
    }
    .is_satisfied_by(&verified));
}

#[test]
fn safety_collateral_and_timeouts_cannot_strengthen_unrelated_coordinates() {
    let mut safety = guarantee_vector_of(CertificateProfile::UnanimousBoundaryClose);
    safety.availability.publication_retrievable = false;
    let verified = CertificateOnlyGuaranteeVerifierV1::verify(&[safety.clone()]).unwrap();
    assert_eq!(
        verified.achieved().safety.model,
        SafetyModelV1::UnanimousAllButOne
    );
    assert!(!verified.achieved().availability.publication_retrievable);

    let mut collateral = guarantee_vector_of(CertificateProfile::HashPcdReference);
    collateral.slashable_collateral = Some(SlashableCollateralV1 {
        asset_id_hash: [1; 32],
        amount_base_units: "100".into(),
        collateral_set_hash: [2; 32],
        bond_snapshot_root: [3; 32],
        locked_until: 99,
        evidence_rule_hash: [4; 32],
        slashing_contract_hash: [5; 32],
        valuation_assumptions_hash: None,
    });
    let verified = CertificateOnlyGuaranteeVerifierV1::verify(&[collateral]).unwrap();
    assert_eq!(verified.achieved().safety.model, SafetyModelV1::Unspecified);
    assert!(verified.achieved().safety.finality_rank.is_none());

    let mut downgraded = safety.clone();
    downgraded.safety.finality_rank = Some(GuaranteeRank::Observational);
    let transformation = GuaranteeTransformV1 {
        schema_version: GuaranteeTransformVersionV1::V1,
        coordinate: GuaranteeCoordinateV1::Safety,
        rule: GuaranteeTransformRuleV1::EstablishSafetyFromIndependentProof,
        input_vector_hashes: BTreeSet::from([safety.commitment().unwrap()]),
        new_evidence_hash: [6; 32],
        theorem_id: "timeout-downgrade-is-not-authority".into(),
        verifier_profile_hash: [7; 32],
        claimed_output_hash: downgraded.commitment().unwrap(),
    };
    assert_eq!(
        CertificateOnlyGuaranteeVerifierV1::verify_claim(
            &[safety],
            &downgraded,
            &[transformation]
        ),
        Err(GuaranteeVectorError::UnsupportedTransformation),
        "a timeout-labelled transform cannot authorize any downgrade or replacement"
    );
}

#[test]
fn classical_endpoint_and_cross_domain_composition_keep_weakest_coordinates() {
    let mut pq_consensus = guarantee_vector_of(CertificateProfile::HashPcdReference);
    pq_consensus.crypto.consensus_pq = true;
    pq_consensus.crypto.channel_pq = true;
    pq_consensus.crypto.externalization_pq = false;
    pq_consensus.crypto.primitive_suites = BTreeSet::from([
        PrimitiveSuiteV1::Sha256,
        PrimitiveSuiteV1::PqAuthenticatedChannel,
        PrimitiveSuiteV1::ClassicalAuthenticatedChannel,
    ]);
    let verified = CertificateOnlyGuaranteeVerifierV1::verify(&[pq_consensus]).unwrap();
    assert!(!verified.achieved().crypto.externalization_pq);
    assert!(!verified.achieved().crypto.end_to_end_pq);

    let mut left = guarantee_vector_of(CertificateProfile::UnanimousBoundaryClose);
    left.safety.configuration_hash = Some([10; 32]);
    left.safety.conflict_domain_hash = Some([11; 32]);
    left.availability.publication_retrievable = true;
    let mut right = left.clone();
    right.safety.conflict_domain_hash = Some([12; 32]);
    right.availability.publication_retrievable = false;
    let verified = CertificateOnlyGuaranteeVerifierV1::verify(&[left, right]).unwrap();
    assert_eq!(verified.achieved().safety.conflict_domain_hash, None);
    assert!(!verified.achieved().availability.publication_retrievable);
    assert!(!GuaranteeRequirementsV1 {
        conflict_domain_hash: Some([11; 32]),
        ..Default::default()
    }
    .is_satisfied_by(&verified));
}

#[test]
fn transform_metadata_is_coordinate_specific_and_evidence_complete() {
    let vector = guarantee_vector_of(CertificateProfile::HashPcdReference);
    let mut transform = GuaranteeTransformV1 {
        schema_version: GuaranteeTransformVersionV1::V1,
        coordinate: GuaranteeCoordinateV1::Availability,
        rule: GuaranteeTransformRuleV1::EstablishSafetyFromIndependentProof,
        input_vector_hashes: BTreeSet::from([vector.commitment().unwrap()]),
        new_evidence_hash: [1; 32],
        theorem_id: "T3".into(),
        verifier_profile_hash: [2; 32],
        claimed_output_hash: [3; 32],
    };
    assert_eq!(
        transform.validate_metadata(),
        Err(GuaranteeVectorError::TransformCoordinateMismatch)
    );
    transform.coordinate = GuaranteeCoordinateV1::Safety;
    transform.new_evidence_hash = [0; 32];
    assert_eq!(
        transform.validate_metadata(),
        Err(GuaranteeVectorError::IncompleteTransformationEvidence)
    );
}
