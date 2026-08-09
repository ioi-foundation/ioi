// W1.6 lane B step 2 — link_owner@v1 is superseded (P0). The unverified owner-anchor store is
// removed: it admits nothing, because admitting an unverified anchor is exactly the INV-40
// defect being closed. The verified path (challenge -> WalletOwnershipProof) lands in steps 3-4.
use super::super::handlers::identity::link_owner;
use super::super::keys::{audit_key, IDENTITY_KEY};
use super::super::support::load_typed;
use super::*;
use ioi_types::app::wallet_network::{
    OwnerAnchor, OwnerWalletCurve, VaultAuditEvent, VaultAuditEventKind, VaultIdentity,
};

fn evm_anchor(link_signature: Vec<u8>) -> OwnerAnchor {
    OwnerAnchor {
        network: "ethereum:mainnet".to_string(),
        address: "0xAb5801a7D398351b8bE11C439e05C5B3259aeC9B".to_string(),
        curve: OwnerWalletCurve::Secp256k1,
        link_signature,
        signature_suite: SignatureSuite::ED25519,
        linked_at_ms: 1_750_000_000_000,
    }
}

#[test]
fn link_owner_refuses_the_unverified_anchor_store_and_persists_nothing() {
    let mut state = MockState::default();
    with_ctx(|ctx| {
        // Even a non-empty link_signature is refused — the point is that NOTHING verified it.
        let error = link_owner(&mut state, ctx, evm_anchor(vec![0xde, 0xad, 0xbe, 0xef]))
            .expect_err("link_owner@v1 must admit no unverified anchor");
        assert!(
            error.to_string().contains("superseded")
                && error.to_string().contains("WalletOwnershipProof"),
            "the refusal must name the verified pipeline that supersedes it: {error}"
        );
    });

    // No identity, and therefore no owner anchor, was written — the unverified store is gone.
    let identity: Option<VaultIdentity> = load_typed(&state, IDENTITY_KEY).expect("state read");
    assert!(
        identity.is_none(),
        "a refused link must persist no identity or owner anchor"
    );

    // The refusal is auditable: the first audit event marks the attempt refused_unverified, so
    // the removal of the unverified path is observable in the same immutable trail.
    let event: VaultAuditEvent = load_typed(&state, &audit_key(0))
        .expect("audit read")
        .expect("the refused attempt is audited at seq 0");
    assert_eq!(event.kind, VaultAuditEventKind::OwnerLinked);
    assert_eq!(
        event.metadata.get("disposition").map(String::as_str),
        Some("refused_unverified"),
        "the refused attempt must be audited as refused_unverified"
    );
}
