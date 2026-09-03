// AFT-CB R6 gate tests — the assumption lattice's four gates:
//   G1  the meet reports the weakest finality-bearing constituent;
//   G2  evidence-only constituents contribute assumptions + pq, never rank;
//   G3  receipts record the finality class and the full assumption vector;
//   G4  pq meets correctly: any non-pq constituent ⇒ non-pq object.
// The fifth gate — adding a CertificateProfile variant without a label is
// a compile error — is `label_of`'s wildcard-free match itself; the
// census test below pins `ALL` so the variant list can't silently drift.

use std::collections::BTreeSet;

#[test]
fn assumption_ids_serialize_to_the_whitepaper_ledger_tokens() {
    let ids = [
        AssumptionId::A1,
        AssumptionId::A2,
        AssumptionId::A3,
        AssumptionId::A4,
        AssumptionId::A5,
        AssumptionId::A6,
        AssumptionId::A7,
        AssumptionId::A8,
        AssumptionId::A9,
        AssumptionId::A10,
    ];
    assert_eq!(
        serde_json::to_value(ids).expect("assumption ids serialize"),
        serde_json::json!(["A1", "A2", "A3", "A4", "A5", "A6", "A7", "A8", "A9", "A10"])
    );
}

#[test]
fn certificate_profile_census_is_exhaustive() {
    // Every listed profile has a constructible label, and the list has
    // no duplicates. `label_of`'s wildcard-free match is the compile
    // gate for NEW variants; this pins the census length so ALL must be
    // extended in the same change.
    let unique: BTreeSet<_> = CertificateProfile::ALL.iter().copied().collect();
    assert_eq!(unique.len(), CertificateProfile::ALL.len());
    assert_eq!(CertificateProfile::ALL.len(), 13);
    for p in CertificateProfile::ALL {
        let _ = label_of(p);
    }
}

#[test]
fn guarantee_ranks_order_weakest_first() {
    assert!(GuaranteeRank::Observational < GuaranteeRank::LiveTierBft);
    assert!(GuaranteeRank::LiveTierBft < GuaranteeRank::SealedAllButOne);
    assert!(GuaranteeRank::SealedAllButOne < GuaranteeRank::SealedAnchored);
}

#[test]
fn meet_reports_weakest_finality_bearing_constituent() {
    // G1: a live QC beside a seal degrades the composition to live-tier.
    let g = assumption_meet(&[
        CertificateProfile::UnanimousBoundaryClose,
        CertificateProfile::GuardianCommitteeCert,
    ])
    .expect("non-empty");
    assert_eq!(g.rank, Some(GuaranteeRank::LiveTierBft));

    // G1 + the observer mutation target: an observer countersignature
    // listed as basis pins the meet at Observational. Mislabeling the
    // observer one level strong (LiveTierBft) turns this RED.
    let g = assumption_meet(&[
        CertificateProfile::ObserverCert,
        CertificateProfile::UnanimousBoundaryClose,
    ])
    .expect("non-empty");
    assert_eq!(g.rank, Some(GuaranteeRank::Observational));

    // An observer-only composition can never authorize live-QC finality.
    let refusal = FinalityReceipt::issue(
        FinalityClass::LiveQc,
        &[CertificateProfile::ObserverCert],
        0,
        0,
    )
    .expect_err("observational basis must refuse LiveQc");
    assert_eq!(
        refusal,
        FinalityRefusal::RankBelowClass {
            class: FinalityClass::LiveQc,
            achieved: GuaranteeRank::Observational,
        }
    );

    // Assumptions UNION (consuming more is weaker): seal + QC consumes
    // the union of both ledgers.
    let g = assumption_meet(&[
        CertificateProfile::UnanimousBoundaryClose,
        CertificateProfile::GuardianCommitteeCert,
    ])
    .expect("non-empty");
    assert_eq!(
        g.assumes,
        BTreeSet::from([
            AssumptionId::A1,
            AssumptionId::A2,
            AssumptionId::A3,
            AssumptionId::A5,
        ])
    );
}

#[test]
fn evidence_only_constituents_never_bear_or_degrade_rank() {
    // G2a: evidence-only composition has NO rank and refuses issuance.
    let g = assumption_meet(&[CertificateProfile::HashPcdReference]).expect("non-empty");
    assert_eq!(g.rank, None);
    let refusal = FinalityReceipt::issue(
        FinalityClass::LiveQc,
        &[CertificateProfile::HashPcdReference],
        0,
        0,
    )
    .expect_err("evidence-only basis must refuse");
    assert_eq!(refusal, FinalityRefusal::NoFinalityBearer);

    // G2b: evidence beside a seal does NOT degrade the seal's rank —
    // but its assumptions still land in the vector.
    let g = assumption_meet(&[
        CertificateProfile::HashPcdReference,
        CertificateProfile::UnanimousBoundaryClose,
    ])
    .expect("non-empty");
    assert_eq!(g.rank, Some(GuaranteeRank::SealedAllButOne));
    assert!(g.assumes.contains(&AssumptionId::A1));

    // G2c: a typed re-genesis root bears no finality in any lineage.
    let g = assumption_meet(&[CertificateProfile::RegenesisRoot]).expect("non-empty");
    assert_eq!(g.rank, None);

    // Empty composition: nothing to grade at all.
    assert_eq!(assumption_meet(&[]), None);
    assert_eq!(
        FinalityReceipt::issue(FinalityClass::LiveQc, &[], 0, 0),
        Err(FinalityRefusal::EmptyComposition)
    );
}

#[test]
fn receipt_records_finality_class_and_assumption_vector() {
    // G3: an issued receipt carries the class and the full vector, and
    // both survive serialization. Stripping the class field from the
    // receipt turns this RED (and fails to compile).
    let receipt = FinalityReceipt::issue(
        FinalityClass::Sealed,
        &[
            CertificateProfile::HashPcdReference,
            CertificateProfile::UnanimousBoundaryClose,
        ],
        30_000,
        250,
    )
    .expect("sealed basis supports Sealed");
    assert_eq!(receipt.class, FinalityClass::Sealed);
    assert_eq!(receipt.guarantee.rank, Some(GuaranteeRank::SealedAllButOne));
    assert_eq!(
        receipt.guarantee.assumes,
        BTreeSet::from([AssumptionId::A1, AssumptionId::A2, AssumptionId::A3])
    );
    assert_eq!(receipt.declared_latency_ms, 30_000);
    assert_eq!(receipt.declared_price_milliunits, 250);

    let json = serde_json::to_value(&receipt).expect("serializes");
    assert_eq!(json["class"], serde_json::json!("Sealed"));
    assert_eq!(
        json["guarantee"]["assumes"],
        serde_json::json!(["A1", "A2", "A3"])
    );

    // The anchored class needs the anchored profile — a bare seal is a
    // typed refusal, never a silent upgrade.
    let refusal = FinalityReceipt::issue(
        FinalityClass::SealedAnchored,
        &[CertificateProfile::UnanimousBoundaryClose],
        0,
        0,
    )
    .expect_err("bare seal must refuse SealedAnchored");
    assert_eq!(
        refusal,
        FinalityRefusal::RankBelowClass {
            class: FinalityClass::SealedAnchored,
            achieved: GuaranteeRank::SealedAllButOne,
        }
    );
    let receipt = FinalityReceipt::issue(
        FinalityClass::SealedAnchored,
        &[CertificateProfile::AnchoredBoundaryClose],
        0,
        0,
    )
    .expect("anchored close supports SealedAnchored");
    assert!(receipt.guarantee.assumes.contains(&AssumptionId::A6));
}

#[test]
fn pq_meets_correctly() {
    // G4: any non-pq constituent makes the object non-pq. The
    // pairing-based live QC is non-pq; marking it pq turns this RED.
    let g = assumption_meet(&[
        CertificateProfile::HashPcdReference,
        CertificateProfile::LiveQuorumCert,
    ])
    .expect("non-empty");
    assert!(!g.pq, "pairing-based constituent must force non-pq");
    assert!(!label_of(CertificateProfile::LiveQuorumCert).pq);

    // The hash-only binding alone IS pq — the AND has a true case, so
    // the assertion above can't pass vacuously.
    let g = assumption_meet(&[CertificateProfile::HashPcdReference]).expect("non-empty");
    assert!(g.pq);

    // The explicitly named PQ profiles are finality-bearing; classical and
    // compatibility profiles remain false rather than inheriting that bit.
    for p in CertificateProfile::ALL {
        let l = label_of(p);
        let expected = matches!(
            p,
            CertificateProfile::PqLiveQuorumCert
                | CertificateProfile::HashAsyncOrderingCert
                | CertificateProfile::PqUnanimousBoundaryClose
                | CertificateProfile::PqAnchoredBoundaryClose
                | CertificateProfile::HashPcdReference
        );
        assert_eq!(l.pq, expected, "{p:?}: explicit PQ profile census");
    }
}

#[test]
fn collapse_object_exposes_shape_derived_guarantee() {
    // Unsealed object: live-tier basis.
    let unsealed = CanonicalCollapseObject::default();
    assert!(unsealed.sealing.is_none());
    let g = unsealed.effective_guarantee().expect("shape has a basis");
    assert_eq!(g.rank, Some(GuaranteeRank::LiveTierBft));
    assert!(g
        .constituents
        .contains(&CertificateProfile::GuardianCommitteeCert));
    assert!(g.constituents.contains(&CertificateProfile::HashPcdReference));
    assert!(!g.pq);

    // Sealed object: the seal alone is the finality basis (two-tier
    // separation) — the rank is SealedAllButOne, not live-tier, and not
    // Observational either (advisory observation is never basis).
    let sealed = CanonicalCollapseObject {
        sealing: Some(Default::default()),
        ..Default::default()
    };
    let g = sealed.effective_guarantee().expect("shape has a basis");
    assert_eq!(g.rank, Some(GuaranteeRank::SealedAllButOne));
    assert!(g
        .constituents
        .contains(&CertificateProfile::UnanimousBoundaryClose));
    assert!(!g.constituents.contains(&CertificateProfile::ObserverCert));
    assert_eq!(
        g.assumes,
        BTreeSet::from([AssumptionId::A1, AssumptionId::A2, AssumptionId::A3])
    );
}
