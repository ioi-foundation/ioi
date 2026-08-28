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

fn signed_chain() -> (Value, Value) {
    let first = signed_bundle();
    let mut next = fixture(
        "../../docs/architecture/_meta/schemas/fixtures/receipt-proof-bundle-v2/positive-offline-single-authority.json",
    );
    next["bundle_id"] = Value::String("proof://acme/2".into());
    next["checkpoint"]["checkpoint_id"] = Value::String("receipt-checkpoint://acme/2".into());
    next["checkpoint"]["finality_certificate"]["certificate_id"] =
        Value::String("finality-certificate://acme/2".into());
    next["checkpoint"]["availability_manifest"]["manifest_id"] =
        Value::String("availability-manifest://acme/2".into());
    next["operations"][0]["sequence"] = json!(1);
    next["receipts"][0]["sequence"] = json!(1);
    next["previous_state_entries"] = first["resulting_state_entries"].clone();
    next["resulting_state_entries"][0]["value_hash"] =
        Value::String(format!("sha256:{}", "22".repeat(32)));
    next["previous_checkpoint"] = first["checkpoint"].clone();
    next["checkpoint"]["previous_checkpoint_ref"] = first["checkpoint"]["checkpoint_id"].clone();
    next["checkpoint"]["previous_checkpoint_hash"] = first["checkpoint"]["body_hash"].clone();
    next["checkpoint"]["previous_canonical_head"] =
        first["checkpoint"]["resulting_canonical_head"].clone();
    next["checkpoint"]["previous_state_commitment"] =
        first["checkpoint"]["resulting_state_commitment"].clone();
    next["checkpoint"]["resulting_state_commitment"]["version"] = json!(2);
    next["checkpoint"]["conflict_authority_binding"]["touched_objects"][0]["previous_version"] =
        json!(1);
    next["checkpoint"]["conflict_authority_binding"]["touched_objects"][0]["resulting_version"] =
        json!(2);
    next["checkpoint"]["conflict_authority_binding"]["touched_objects"][0]["previous_head"] = first
        ["checkpoint"]["conflict_authority_binding"]["touched_objects"][0]["resulting_head"]
        .clone();
    next["checkpoint"]["conflict_authority_binding"]["touched_objects"][0]["resulting_head"] =
        next["resulting_state_entries"][0]["value_hash"].clone();
    let signing_key = Ed25519PrivateKey::from_bytes(&[7_u8; 32]).expect("test key");
    let next = emit_single_authority(next, "key://acme/finality/1", &signing_key)
        .expect("chained fixture emits");
    (first, next)
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
fn declared_payload_availability_is_recomputed_offline() {
    let mut template = fixture(
        "../../docs/architecture/_meta/schemas/fixtures/receipt-proof-bundle-v2/positive-offline-single-authority.json",
    );
    template["requested_axes"] = json!(["availability"]);
    template["checkpoint"]["finality_certificate"]["claimed_axes"] = json!(["availability"]);
    template["checkpoint"]["verifier_contract"]["axes"] = json!([{
        "axis": "availability",
        "required_input_contract_ids": [
            "schema://ioi/foundations/receipt-proof-bundle/v2",
            "schema://ioi/foundations/availability-manifest/v1"
        ],
        "failure_behavior": "fail_closed"
    }]);
    template["checkpoint"]["availability_manifest"]["payloads"] = json!([{
        "payload_ref": "payload://acme/hello",
        "payload_hash": "sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
        "byte_length": 5,
        "location_refs": ["location://acme/local/hello"],
        "failure_domain_refs": ["failure-domain://acme/local"],
        "retrieval_evidence_refs": ["evidence://acme/hello/retrieved"]
    }]);
    template["availability_payloads"] = json!([{
        "payload_ref": "payload://acme/hello",
        "payload_base64": "aGVsbG8="
    }]);
    let signing_key = Ed25519PrivateKey::from_bytes(&[7_u8; 32]).expect("test key");
    let bundle = emit_single_authority(template, "key://acme/finality/1", &signing_key)
        .expect("availability fixture emits");
    assert_eq!(
        verify_bundle(&bundle)
            .expect("availability verifies")
            .established_axes,
        vec!["availability"]
    );
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
        set_text(&mut bundle, "bundle_hash", outer_hash).expect("rewrite unsigned outer hash");
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

    let mut recognition = fixture(
        "../../docs/architecture/_meta/schemas/fixtures/receipt-proof-bundle-v2/positive-offline-single-authority.json",
    );
    recognition["checkpoint"]["recognition"]["recognition_class"] = Value::String("K7".into());
    recognition["checkpoint"]["recognition"]["ordinary_admission_permitted"] = json!(false);
    let signing_key = Ed25519PrivateKey::from_bytes(&[7_u8; 32]).expect("test key");
    assert!(matches!(
        emit_single_authority(recognition, "key://acme/finality/1", &signing_key),
        Err(VerificationError::UnsupportedRecognition { .. })
    ));
}

#[test]
fn predecessor_body_substitution_is_recomputed_and_refused() {
    let (_first, mut next) = signed_chain();
    next["previous_checkpoint"]["resulting_canonical_head"] =
        Value::String(format!("sha256:{}", "99".repeat(32)));
    let outer_hash =
        hash_value(&without(&next, &["bundle_hash"]).expect("outer preimage")).expect("outer hash");
    set_text(&mut next, "bundle_hash", outer_hash).expect("rewrite unsigned outer hash");
    assert!(verify_bundle(&next).is_err());
}

#[test]
fn certificate_cannot_claim_unverified_availability() {
    let mut template = fixture(
        "../../docs/architecture/_meta/schemas/fixtures/receipt-proof-bundle-v2/positive-offline-single-authority.json",
    );
    template["checkpoint"]["finality_certificate"]["claimed_axes"] =
        json!(["integrity", "availability"]);
    template["checkpoint"]["verifier_contract"]["axes"] = json!([
        {
            "axis": "integrity",
            "required_input_contract_ids": ["schema://ioi/foundations/receipt-proof-bundle/v2"],
            "failure_behavior": "fail_closed"
        },
        {
            "axis": "availability",
            "required_input_contract_ids": ["schema://ioi/foundations/availability-manifest/v1"],
            "failure_behavior": "fail_closed"
        }
    ]);
    template["checkpoint"]["availability_manifest"]["claim_status"] =
        Value::String("declared".into());
    let signing_key = Ed25519PrivateKey::from_bytes(&[7_u8; 32]).expect("test key");
    assert!(emit_single_authority(template, "key://acme/finality/1", &signing_key).is_err());
}

#[test]
fn same_epoch_predecessor_cannot_change_issuer_key() {
    let (_first, mut next) = signed_chain();
    let predecessor = &mut next["previous_checkpoint"];
    let certificate = &mut predecessor["finality_certificate"];
    let replacement_key = Ed25519PrivateKey::from_bytes(&[8_u8; 32]).expect("replacement key");
    let replacement_public = replacement_key
        .public_key()
        .expect("replacement public key");
    certificate["issuer_key_id"] = Value::String("key://acme/finality/replacement".into());
    certificate["issuer_public_key"] = Value::String(hex::encode(replacement_public.to_bytes()));
    let certificate_hash = hash_value(
        &without(certificate, &["body_hash", "signature"]).expect("certificate preimage"),
    )
    .expect("certificate hash");
    certificate["body_hash"] = Value::String(certificate_hash.clone());
    let signature = replacement_key
        .sign(format!("ioi.finality-certificate.v1\0{certificate_hash}").as_bytes())
        .expect("replacement signature");
    certificate["signature"] = Value::String(hex::encode(signature.to_bytes()));
    let outer_hash =
        hash_value(&without(&next, &["bundle_hash"]).expect("outer preimage")).expect("outer hash");
    set_text(&mut next, "bundle_hash", outer_hash).expect("rewrite unsigned outer hash");
    assert!(verify_bundle(&next).is_err());
}

#[test]
fn recognition_and_binding_invariant_domains_must_match() {
    let mut template = fixture(
        "../../docs/architecture/_meta/schemas/fixtures/receipt-proof-bundle-v2/positive-offline-single-authority.json",
    );
    template["checkpoint"]["recognition"]["invariant_domain_refs"] =
        json!(["invariant://acme/substituted"]);
    let signing_key = Ed25519PrivateKey::from_bytes(&[7_u8; 32]).expect("test key");
    assert!(emit_single_authority(template, "key://acme/finality/1", &signing_key).is_err());
}
