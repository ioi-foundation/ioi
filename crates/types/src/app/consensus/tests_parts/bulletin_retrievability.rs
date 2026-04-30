#[test]
fn canonical_bulletin_close_retrievability_anchor_requires_all_hashes_or_none() {
    let (_, ordered_transactions, certificate) =
        sample_committed_surface_ordering_fixture(12, 2, 14);
    let mut close = build_canonical_bulletin_close(
        &certificate.bulletin_commitment,
        &certificate.bulletin_availability_certificate,
    )
    .expect("build bulletin close");

    assert!(canonical_bulletin_close_retrievability_anchor(&close)
        .expect("read empty anchor")
        .is_none());
    assert!(set_canonical_bulletin_close_retrievability_anchor(
        &mut close, [1u8; 32], [0u8; 32], [2u8; 32],
    )
    .is_err());

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
        canonical_bulletin_close_retrievability_anchor(&close).expect("read anchored close"),
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
        bulletin_retrievability_profile_hash: canonical_bulletin_retrievability_profile_hash(
            &profile,
        )
        .expect("profile hash"),
        bulletin_shard_manifest_hash: canonical_bulletin_shard_manifest_hash(&manifest)
            .expect("manifest hash"),
        bulletin_custody_assignment_hash: canonical_bulletin_custody_assignment_hash(&assignment)
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
        canonical_bulletin_retrievability_challenge_hash(&challenge).expect("challenge hash"),
        [0u8; 32]
    );

    assert!(validate_bulletin_retrievability_challenge(
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
    .is_err());
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
    let assignment = build_bulletin_custody_assignment(&profile, &manifest, &validator_set)
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
    assert!(validate_bulletin_retrievability_challenge(
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
    .is_err());

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
        bulletin_retrievability_profile_hash: canonical_bulletin_retrievability_profile_hash(
            &profile,
        )
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
    assert!(validate_bulletin_retrievability_challenge(
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
    .is_err());

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
        bulletin_retrievability_profile_hash: canonical_bulletin_retrievability_profile_hash(
            &profile,
        )
        .expect("profile hash"),
        bulletin_shard_manifest_hash: canonical_bulletin_shard_manifest_hash(&manifest)
            .expect("manifest hash"),
        bulletin_custody_assignment_hash: canonical_bulletin_custody_assignment_hash(&assignment)
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
    assert!(validate_bulletin_retrievability_challenge(
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
    .is_err());
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
        bulletin_retrievability_profile_hash: canonical_bulletin_retrievability_profile_hash(
            &profile,
        )
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
    assert!(validate_bulletin_retrievability_challenge(
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
    .is_err());
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
    let assignment = build_bulletin_custody_assignment(&profile, &manifest, &validator_set)
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
        bulletin_retrievability_profile_hash: canonical_bulletin_retrievability_profile_hash(
            &profile,
        )
        .expect("profile hash"),
        bulletin_shard_manifest_hash: super::canonical_bulletin_shard_manifest_hash(&manifest)
            .expect("manifest hash"),
        bulletin_custody_assignment_hash: canonical_bulletin_custody_assignment_hash(&assignment)
            .expect("assignment hash"),
        bulletin_custody_receipt_hash: canonical_bulletin_custody_receipt_hash(&receipt)
            .expect("receipt hash"),
        bulletin_custody_response_hash: [0u8; 32],
        details: "published custody receipt contradicts the deterministic manifest binding".into(),
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
    assert!(validate_bulletin_retrievability_challenge(
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
    .is_err());
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
        bulletin_retrievability_profile_hash: canonical_bulletin_retrievability_profile_hash(
            &profile,
        )
        .expect("profile hash"),
        bulletin_shard_manifest_hash: canonical_bulletin_shard_manifest_hash(&manifest)
            .expect("manifest hash"),
        bulletin_custody_assignment_hash: canonical_bulletin_custody_assignment_hash(&assignment)
            .expect("assignment hash"),
        bulletin_custody_receipt_hash: canonical_bulletin_custody_receipt_hash(&receipt)
            .expect("receipt hash"),
        bulletin_custody_response_hash: canonical_bulletin_custody_response_hash(&response)
            .expect("response hash"),
        details: "published bulletin entries do not reconstruct the canonical bulletin surface"
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

    assert!(validate_bulletin_retrievability_challenge(
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
    .is_err());
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
    let manifest_hash = canonical_bulletin_shard_manifest_hash(&manifest).expect("manifest hash");
    let receipt_hash = canonical_bulletin_custody_receipt_hash(&receipt).expect("receipt hash");
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
    assert!(extract_endogenous_canonical_bulletin_surface(
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
    .is_err());
}

