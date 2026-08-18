// AFT-CB P4.3 — structural wire-cost measurements. These are EXACT
// (SCALE-encoded byte sizes of the canonical objects) and reproduce with
// zero variance: the test pins each size, so a wire-format change that
// moves a cost updates the pinned number here and is visible in review.
// The memo (specs/p4_measured_costs.md) cites these figures.

#[test]
fn measured_wire_costs_are_pinned() {
    use crate::codec;

    // The custody / validate-and-hold binding (T3): the object whose
    // signature MEANS validate-and-hold. This is the per-slot standing
    // cost — NOT a per-holder audit record.
    let availability = BulletinAvailabilityCertificate {
        height: 1,
        bulletin_commitment_hash: [0x11; 32],
        recoverability_root: [0x22; 32],
    };
    let availability_bytes = codec::to_bytes_canonical(&availability).unwrap().len();

    // The canonical bulletin close (the sealed-slot commitment).
    let close = CanonicalBulletinClose {
        height: 1,
        cutoff_timestamp_ms: 1_770_000_000,
        bulletin_commitment_hash: [0x11; 32],
        bulletin_availability_certificate_hash: [0x22; 32],
        bulletin_retrievability_profile_hash: [0x33; 32],
        bulletin_shard_manifest_hash: [0x44; 32],
        bulletin_custody_receipt_hash: [0x55; 32],
        entry_count: 128,
    };
    let close_bytes = codec::to_bytes_canonical(&close).unwrap().len();

    // The OPTIONAL audit-enforcement record (R2): the additive
    // per-probe cost. A close verifies with ZERO of these, so this is
    // the marginal cost of the audit lane, paid only when a probe is
    // recorded.
    let audit = AvailabilityAuditRecord {
        height: 1,
        auditor_account_id: AccountId([0x01; 32]),
        holder_account_id: AccountId([0x02; 32]),
        tx_hash: [0x03; 32],
        outcome: AvailabilityAuditOutcome::Served,
        details: String::new(),
    };
    let audit_bytes = codec::to_bytes_canonical(&audit).unwrap().len();

    // Pinned exact sizes (bytes). Any wire-format change surfaces here.
    assert_eq!(availability_bytes, 72, "validate-and-hold binding");
    assert_eq!(close_bytes, 180, "canonical bulletin close");
    assert_eq!(audit_bytes, 106, "optional audit record (marginal, zero at rest)");
}
