use super::*;
use std::fs;
use std::path::PathBuf;

fn fixture(relative: &str) -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(relative);
    serde_json::from_str(&fs::read_to_string(path).expect("fixture readable"))
        .expect("fixture parses")
}

fn signed_bundle() -> Value {
    let template = fixture(
        "../../docs/architecture/_meta/schemas/fixtures/receipt-proof-bundle-v2/positive-offline-single-authority.json",
    );
    let signing_key = Ed25519PrivateKey::from_bytes(&[7_u8; 32]).expect("test key");
    emit_single_authority(template, "key://acme/finality/1", &signing_key)
        .expect("supported fixture emits")
}

#[test]
fn emitted_single_authority_bundle_verifies_offline() {
    let bundle = signed_bundle();
    let claim = verify_bundle(&bundle).expect("emitted bundle verifies");
    assert_eq!(claim.profile, "single_authority");
    assert_eq!(claim.certificate_variant, "single_authority_v1");
    assert_eq!(claim.established_axes, vec!["integrity"]);
}

#[test]
fn every_registered_substitution_fails_closed() {
    let mutations = fixture("tests/fixtures/receipt-proof-v2-substitutions.json");
    for mutation in mutations.as_array().expect("mutation array") {
        let mut bundle = signed_bundle();
        let pointer = text(mutation, "pointer").expect("pointer");
        let replacement = field(mutation, "replacement").expect("replacement").clone();
        *bundle
            .pointer_mut(&pointer)
            .expect("mutation pointer exists") = replacement;
        let outer_hash = hash_value(&without(&bundle, &["bundle_hash"]).expect("outer preimage"))
            .expect("outer hash");
        set_text(&mut bundle, "bundle_hash", outer_hash)
            .expect("rewrite unsigned outer hash");
        assert!(
            verify_bundle(&bundle).is_err(),
            "substitution {} unexpectedly verified",
            text(mutation, "id").expect("mutation id")
        );
    }
}

#[test]
fn unsupported_profile_and_axis_are_unavailable() {
    let mut profile = signed_bundle();
    profile["checkpoint"]["profile"] = Value::String("bft_consensus".into());
    profile["checkpoint"]["finality_certificate"]["profile"] =
        Value::String("bft_consensus".into());
    profile["checkpoint"]["finality_certificate"]["certificate_variant"] =
        Value::String("bft_consensus_aft_v1".into());
    assert!(matches!(
        verify_bundle(&profile),
        Err(VerificationError::UnsupportedProfile { .. })
    ));

    let mut axis = signed_bundle();
    axis["requested_axes"] = json!(["currentness"]);
    assert_eq!(
        verify_bundle(&axis),
        Err(VerificationError::UnsupportedAxis("currentness".into()))
    );
}
