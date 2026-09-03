use super::*;
use crate::app::consensus::{
    guarantee_vector_of, CertificateOnlyGuaranteeVerifierV1, CertificateProfile,
    GuaranteeRequirementsV1, SlashableCollateralRequirementV1,
};

fn evidence(behavior: SlashableBehaviorV1) -> AccountabilityEvidenceV1 {
    AccountabilityEvidenceV1 {
        schema_version: EconomicAssuranceVersionV1::V1,
        configuration_hash: [1; 32],
        behavior,
        evidence_predicate_hash: [2; 32],
        evidence_hash: [3; 32],
        implicated_members: BTreeSet::from([[10; 32], [11; 32]]),
        challenge_horizon_end: 200,
    }
}

fn bond(id: u8, owner: u8, amount: &str) -> CollateralBondV1 {
    CollateralBondV1 {
        bond_id: [id; 32],
        collateral_id: [id + 20; 32],
        owner_member_hash: [owner; 32],
        asset_id_hash: [4; 32],
        amount_base_units: amount.into(),
        exclusive_configuration_hash: [1; 32],
        locked_from: 50,
        locked_until: 250,
        challenge_horizon_end: 200,
        evidence_predicate_hash: [2; 32],
        slashing_contract_hash: [5; 32],
        active_encumbrance_hashes: BTreeSet::new(),
        withdrawal_pending: false,
    }
}

fn snapshot() -> BondSnapshotV1 {
    BondSnapshotV1 {
        schema_version: EconomicAssuranceVersionV1::V1,
        snapshot_height: 100,
        configuration_hash: [1; 32],
        bonds: vec![bond(1, 10, "999999999999999999999999"), bond(2, 11, "2")],
    }
}

fn claim(evidence: &AccountabilityEvidenceV1, snapshot: &BondSnapshotV1) -> EconomicAssuranceV1 {
    EconomicAssuranceV1 {
        schema_version: EconomicAssuranceVersionV1::V1,
        asset_id_hash: [4; 32],
        amount_base_units: "1000000000000000000000001".into(),
        configuration_hash: [1; 32],
        collateral_set_hash: commitment(
            COLLATERAL_SET_V1_DOMAIN,
            &snapshot
                .bonds
                .iter()
                .map(|bond| bond.collateral_id)
                .collect::<Vec<_>>(),
        )
        .unwrap(),
        bond_snapshot_root: snapshot.commitment().unwrap(),
        snapshot_height: 100,
        locked_until: 250,
        challenge_horizon_end: evidence.challenge_horizon_end,
        evidence_predicate: evidence.behavior,
        evidence_predicate_hash: [2; 32],
        slashing_contract_hash: [5; 32],
        valuation_assumptions: None,
    }
}

#[test]
fn offline_verifier_recomputes_unbounded_distinct_floor_and_attaches_it() {
    let evidence = evidence(SlashableBehaviorV1::ConflictingSignedStatements);
    let snapshot = snapshot();
    let claimed = claim(&evidence, &snapshot);
    let verified = EconomicAssuranceVerifierV1::verify(&evidence, &snapshot, &claimed).unwrap();
    assert_eq!(
        verified.assurance().amount_base_units,
        "1000000000000000000000001"
    );

    let base = CertificateOnlyGuaranteeVerifierV1::verify(&[guarantee_vector_of(
        CertificateProfile::UnanimousBoundaryClose,
    )])
    .unwrap();
    let augmented = verified.attach_to(&base).unwrap();
    assert_eq!(
        augmented
            .achieved()
            .slashable_collateral
            .as_ref()
            .unwrap()
            .amount_base_units,
        claimed.amount_base_units
    );
    assert!(augmented
        .achieved()
        .constituent_hashes
        .contains(&verified.proof_commitment()));
    let policy = GuaranteeRequirementsV1 {
        minimum_slashable_collateral: Some(SlashableCollateralRequirementV1 {
            asset_id_hash: [4; 32],
            minimum_amount_base_units: "1000000000000000000000000".into(),
        }),
        ..Default::default()
    };
    assert!(policy.is_satisfied_by(&augmented));
}

#[test]
fn policy_join_uses_exact_asset_and_arbitrary_precision_maximum() {
    let lower = GuaranteeRequirementsV1 {
        minimum_slashable_collateral: Some(SlashableCollateralRequirementV1 {
            asset_id_hash: [4; 32],
            minimum_amount_base_units: "999999999999999999999999".into(),
        }),
        ..Default::default()
    };
    let higher = GuaranteeRequirementsV1 {
        minimum_slashable_collateral: Some(SlashableCollateralRequirementV1 {
            asset_id_hash: [4; 32],
            minimum_amount_base_units: "1000000000000000000000000".into(),
        }),
        ..Default::default()
    };
    assert_eq!(
        lower
            .join(&higher)
            .unwrap()
            .minimum_slashable_collateral
            .unwrap()
            .minimum_amount_base_units,
        "1000000000000000000000000"
    );

    let different_asset = GuaranteeRequirementsV1 {
        minimum_slashable_collateral: Some(SlashableCollateralRequirementV1 {
            asset_id_hash: [9; 32],
            minimum_amount_base_units: "1".into(),
        }),
        ..Default::default()
    };
    assert!(lower.join(&different_asset).is_err());
}

#[test]
fn duplicate_bond_and_underlying_lot_attacks_are_rejected() {
    let evidence = evidence(SlashableBehaviorV1::ConflictingSignedStatements);
    let mut duplicate_bond = snapshot();
    duplicate_bond.bonds[1].bond_id = duplicate_bond.bonds[0].bond_id;
    let claimed = claim(&evidence, &duplicate_bond);
    assert_eq!(
        EconomicAssuranceVerifierV1::verify(&evidence, &duplicate_bond, &claimed),
        Err(EconomicAssuranceError::NonCanonicalOrDuplicateBond)
    );

    let mut duplicate_lot = snapshot();
    duplicate_lot.bonds[1].collateral_id = duplicate_lot.bonds[0].collateral_id;
    let claimed = claim(&evidence, &duplicate_lot);
    assert_eq!(
        EconomicAssuranceVerifierV1::verify(&evidence, &duplicate_lot, &claimed),
        Err(EconomicAssuranceError::DuplicateCollateralLot)
    );
}

#[test]
fn shared_unlocked_expired_and_encumbered_collateral_are_rejected() {
    let evidence = evidence(SlashableBehaviorV1::InvalidSignedAttestation);
    for (snapshot, expected) in [
        {
            let mut value = snapshot();
            value.bonds[0].exclusive_configuration_hash = [9; 32];
            (value, EconomicAssuranceError::SharedCollateral)
        },
        {
            let mut value = snapshot();
            value.bonds[0].locked_from = 101;
            (value, EconomicAssuranceError::UnlockedCollateral)
        },
        {
            let mut value = snapshot();
            value.bonds[0].locked_until = 199;
            (value, EconomicAssuranceError::ExpiredCollateral)
        },
        {
            let mut value = snapshot();
            value.bonds[0].active_encumbrance_hashes.insert([8; 32]);
            (value, EconomicAssuranceError::EncumberedCollateral)
        },
    ] {
        let claimed = claim(&evidence, &snapshot);
        assert_eq!(
            EconomicAssuranceVerifierV1::verify(&evidence, &snapshot, &claimed),
            Err(expected)
        );
    }
}

#[test]
fn silence_remains_unpriced_and_missing_member_coverage_fails_closed() {
    let silence = evidence(SlashableBehaviorV1::WithholdingOrSilence);
    let silence_snapshot = snapshot();
    let claimed = claim(&silence, &silence_snapshot);
    assert_eq!(
        EconomicAssuranceVerifierV1::verify(&silence, &silence_snapshot, &claimed),
        Err(EconomicAssuranceError::UnpriceableBehavior)
    );

    let signed = evidence(SlashableBehaviorV1::ConflictingSignedStatements);
    let mut incomplete = snapshot();
    incomplete.bonds.pop();
    let claimed = claim(&signed, &incomplete);
    assert_eq!(
        EconomicAssuranceVerifierV1::verify(&signed, &incomplete, &claimed),
        Err(EconomicAssuranceError::MissingImplicatedMemberBond)
    );
}

#[test]
fn forged_amount_and_stale_oracle_assumptions_are_rejected() {
    let evidence = evidence(SlashableBehaviorV1::ConflictingSignedStatements);
    let snapshot = snapshot();
    let mut forged = claim(&evidence, &snapshot);
    forged.amount_base_units = "1000000000000000000000002".into();
    assert_eq!(
        EconomicAssuranceVerifierV1::verify(&evidence, &snapshot, &forged),
        Err(EconomicAssuranceError::ClaimMismatch)
    );

    let mut stale = claim(&evidence, &snapshot);
    stale.valuation_assumptions = Some(ValuationAssumptionsV1 {
        quote_asset_id_hash: [6; 32],
        oracle_profile_hash: [7; 32],
        observed_at: 90,
        valid_until: 99,
        price_numerator: "2".into(),
        price_denominator: "1".into(),
    });
    assert_eq!(
        EconomicAssuranceVerifierV1::verify(&evidence, &snapshot, &stale),
        Err(EconomicAssuranceError::InvalidValuationAssumptions)
    );
}

#[test]
fn live_valuation_assumptions_remain_visible_in_coordinate_commitment() {
    let evidence = evidence(SlashableBehaviorV1::ConflictingSignedStatements);
    let snapshot = snapshot();
    let mut claimed = claim(&evidence, &snapshot);
    claimed.valuation_assumptions = Some(ValuationAssumptionsV1 {
        quote_asset_id_hash: [6; 32],
        oracle_profile_hash: [7; 32],
        observed_at: 90,
        valid_until: 110,
        price_numerator: "2".into(),
        price_denominator: "1".into(),
    });
    let verified = EconomicAssuranceVerifierV1::verify(&evidence, &snapshot, &claimed).unwrap();
    assert!(verified
        .assurance()
        .valuation_assumptions
        .as_ref()
        .is_some());
    assert!(verified
        .assurance()
        .coordinate()
        .unwrap()
        .valuation_assumptions_hash
        .is_some());
}
