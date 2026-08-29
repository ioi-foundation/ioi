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
    assert_eq!(claim.issuer_key_id, "key://acme/finality/1");
    assert_eq!(claim.issuer_public_key.len(), 64);
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
    // `threshold_authority` is a canonical member this crate does not implement:
    // it refuses as unimplemented rather than degrading to a member it can check.
    let mut profile = signed_bundle();
    profile["checkpoint"]["profile"] = Value::String("threshold_authority".into());
    profile["checkpoint"]["finality_certificate"]["profile"] =
        Value::String("threshold_authority".into());
    profile["checkpoint"]["finality_certificate"]["certificate_variant"] =
        Value::String("threshold_authority_v1".into());
    assert!(matches!(
        verify_bundle(&profile),
        Err(VerificationError::UnsupportedProfile { .. })
    ));

    // Relabelling a single-authority bundle as BFT does not make it one: the
    // certificate carries no quorum evidence, so it refuses before anything
    // reads the label as peer safety.
    let mut relabelled = signed_bundle();
    relabelled["checkpoint"]["profile"] = Value::String("bft_consensus".into());
    relabelled["checkpoint"]["finality_certificate"]["profile"] =
        Value::String("bft_consensus".into());
    relabelled["checkpoint"]["finality_certificate"]["certificate_variant"] =
        Value::String("bft_consensus_aft_v1".into());
    assert!(matches!(
        verify_bundle(&relabelled),
        Err(VerificationError::ConsensusEvidence(_))
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

#[test]
fn empty_or_ephemeral_availability_claim_fails_closed() {
    let mut template = fixture(
        "../../docs/architecture/_meta/schemas/fixtures/receipt-proof-bundle-v2/positive-offline-single-authority.json",
    );
    template["requested_axes"] = json!(["availability"]);
    template["checkpoint"]["finality_certificate"]["claimed_axes"] = json!(["availability"]);
    template["checkpoint"]["verifier_contract"]["axes"] = json!([{
        "axis": "availability",
        "required_input_contract_ids": ["schema://ioi/foundations/availability-manifest/v1"],
        "failure_behavior": "fail_closed"
    }]);
    let signing_key = Ed25519PrivateKey::from_bytes(&[7_u8; 32]).expect("test key");
    assert!(
        emit_single_authority(template.clone(), "key://acme/finality/1", &signing_key).is_err()
    );

    template["checkpoint"]["availability_manifest"]["retention"]["retention_class"] =
        Value::String("ephemeral_until_ack".into());
    template["checkpoint"]["retention_class"] = Value::String("ephemeral_until_ack".into());
    template["checkpoint"]["availability_manifest"]["payloads"] = json!([{
        "payload_ref": "payload://acme/hello",
        "payload_hash": "sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
        "byte_length": 5,
        "location_refs": ["location://acme/local/hello"],
        "failure_domain_refs": ["failure-domain://acme/local"],
        "retrieval_evidence_refs": []
    }]);
    template["availability_payloads"] = json!([{
        "payload_ref": "payload://acme/hello",
        "payload_base64": "aGVsbG8="
    }]);
    assert!(emit_single_authority(template, "key://acme/finality/1", &signing_key).is_err());
}

#[test]
fn unavailable_declared_verifier_input_refuses() {
    let mut template = fixture(
        "../../docs/architecture/_meta/schemas/fixtures/receipt-proof-bundle-v2/positive-offline-single-authority.json",
    );
    template["checkpoint"]["verifier_contract"]["axes"][0]["required_input_contract_ids"] =
        json!(["schema://acme/unavailable/v1"]);
    let signing_key = Ed25519PrivateKey::from_bytes(&[7_u8; 32]).expect("test key");
    assert!(emit_single_authority(template, "key://acme/finality/1", &signing_key).is_err());
}

// ---------------------------------------------------------------------------
// bft_consensus / bft_consensus_aft_v1
// ---------------------------------------------------------------------------

const BFT_TEMPLATE: &str = "tests/fixtures/template-offline-bft-consensus.json";

/// Four distinct member keys. The template carries placeholder public keys
/// because a fixture cannot contain a signature over a checkpoint that does not
/// exist yet; the real keys are injected here and the votes are cast over the
/// prepared vote message.
fn bft_member_keys() -> Vec<Ed25519PrivateKey> {
    (0..4_u8)
        .map(|index| Ed25519PrivateKey::from_bytes(&[11 + index; 32]).expect("member key"))
        .collect()
}

fn bft_template() -> Value {
    let mut template = fixture(BFT_TEMPLATE);
    for (index, key) in bft_member_keys().iter().enumerate() {
        let public = key.public_key().expect("member public key");
        template["checkpoint"]["finality_certificate"]["consensus_evidence"]["members"][index]
            ["public_key"] = Value::String(hex::encode(public.to_bytes()));
    }
    template
}

fn bft_bundle_from(
    template: Value,
    voters: &[usize],
    issuer: &Ed25519PrivateKey,
) -> Result<Value, VerificationError> {
    let keys = bft_member_keys();
    let prepared = prepare_checkpoint(template, "bft_consensus")?;
    let message = prepared
        .vote_message()
        .expect("bft_consensus prepares a vote message")
        .to_vec();
    let votes = voters
        .iter()
        .map(|index| BftVote {
            member_ref: format!("node://acme/aft/{index}"),
            signature: hex::encode(
                keys[*index]
                    .sign(&message)
                    .expect("member signature")
                    .to_bytes(),
            ),
        })
        .collect::<Vec<_>>();
    finalize_bft_consensus(prepared, &votes, "key://acme/finality/1", issuer)
}

fn signed_bft_bundle() -> Value {
    bft_bundle_from(bft_template(), &[0, 1, 2], &bft_member_keys()[0])
        .expect("bft fixture emits and self-verifies")
}

#[test]
fn emitted_bft_consensus_bundle_verifies_offline() {
    let bundle = signed_bft_bundle();
    let claim = verify_bundle(&bundle).expect("emitted bft bundle verifies");
    assert_eq!(claim.profile, "bft_consensus");
    assert_eq!(claim.certificate_variant, "bft_consensus_aft_v1");
    let quorum = claim.quorum.expect("bft claims a quorum");
    assert_eq!(quorum.total_voting_members, 4);
    assert_eq!(quorum.byzantine_fault_tolerance, 1);
    assert_eq!(quorum.quorum_threshold, 3);
    assert_eq!(quorum.distinct_member_signatures_verified, 3);
    assert_eq!(quorum.membership_ref, "node-membership://acme/aft/1");
    assert!(quorum.membership_hash.starts_with("sha256:"));
}

#[test]
fn single_authority_claims_no_quorum_rather_than_an_empty_one() {
    let claim = verify_bundle(&signed_bundle()).expect("verifies");
    assert_eq!(claim.quorum, None);
}

#[test]
fn a_verified_quorum_does_not_establish_non_equivocation() {
    // The exact claim boundary: a quorum over one checkpoint says nothing about
    // whether the same members also signed a conflicting one at the same view.
    let bundle = signed_bft_bundle();
    let claim = verify_bundle(&bundle).expect("emitted bft bundle verifies");
    assert_eq!(claim.established_axes, vec!["integrity"]);
    assert!(claim.quorum.is_some());
    assert!(UNESTABLISHED_AXES.contains(&"non_equivocation"));

    let mut promoted = bundle;
    promoted["requested_axes"] = json!(["non_equivocation"]);
    assert_eq!(
        verify_bundle(&promoted),
        Err(VerificationError::UnsupportedAxis("non_equivocation".into()))
    );
}

#[test]
fn every_registered_bft_substitution_fails_closed() {
    let mutations = fixture("tests/fixtures/receipt-proof-v2-bft-substitutions.json");
    for mutation in mutations.as_array().expect("mutation array") {
        let mut bundle = signed_bft_bundle();
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
fn one_signer_holding_every_seat_is_not_a_quorum() {
    // The membership hash is recomputed during prepare, so this isolates the
    // distinct-key rule: the evidence is internally consistent and every
    // signature is valid; it is refused because four seats hold one key.
    let mut template = bft_template();
    let sole = bft_member_keys()[0].public_key().expect("public key");
    for index in 0..4_usize {
        template["checkpoint"]["finality_certificate"]["consensus_evidence"]["members"][index]
            ["public_key"] = Value::String(hex::encode(sole.to_bytes()));
    }
    let keys = bft_member_keys();
    let prepared = prepare_checkpoint(template, "bft_consensus").expect("prepares");
    let message = prepared.vote_message().expect("vote message").to_vec();
    let votes = (0..3_usize)
        .map(|index| BftVote {
            member_ref: format!("node://acme/aft/{index}"),
            signature: hex::encode(keys[0].sign(&message).expect("signature").to_bytes()),
        })
        .collect::<Vec<_>>();
    let refusal = finalize_bft_consensus(prepared, &votes, "key://acme/finality/1", &keys[0])
        .expect_err("one key holding every seat is refused");
    match refusal {
        VerificationError::ConsensusEvidence(detail) => {
            assert!(detail.contains("duplicate member public key"), "{detail}");
        }
        other => panic!("unexpected refusal: {other}"),
    }
}

#[test]
fn a_membership_that_cannot_tolerate_its_declared_faults_refuses() {
    let mut template = bft_template();
    template["checkpoint"]["finality_certificate"]["consensus_evidence"]
        ["byzantine_fault_tolerance"] = json!(2);
    template["checkpoint"]["finality_certificate"]["consensus_evidence"]["quorum_threshold"] =
        json!(5);
    let refusal = bft_bundle_from(template, &[0, 1, 2], &bft_member_keys()[0])
        .expect_err("four members cannot tolerate two byzantine faults");
    match refusal {
        VerificationError::ConsensusEvidence(detail) => {
            assert!(detail.contains("cannot tolerate"), "{detail}");
        }
        other => panic!("unexpected refusal: {other}"),
    }
}

#[test]
fn a_vote_set_below_the_declared_threshold_refuses() {
    let mut template = bft_template();
    template["checkpoint"]["finality_certificate"]["consensus_evidence"]["quorum_threshold"] =
        json!(4);
    let refusal = bft_bundle_from(template, &[0, 1, 2], &bft_member_keys()[0])
        .expect_err("three votes do not meet a threshold of four");
    match refusal {
        VerificationError::ConsensusEvidence(detail) => {
            assert!(
                detail.contains("below the declared quorum threshold"),
                "{detail}"
            );
        }
        other => panic!("unexpected refusal: {other}"),
    }
}

#[test]
fn the_issuer_must_be_a_member_that_voted_in_the_quorum() {
    let outsider = Ed25519PrivateKey::from_bytes(&[7_u8; 32]).expect("outsider key");
    let refusal = bft_bundle_from(bft_template(), &[0, 1, 2], &outsider)
        .expect_err("an outsider may not aggregate a quorum");
    match refusal {
        VerificationError::ConsensusEvidence(detail) => {
            assert!(detail.contains("not a declared voting member"), "{detail}");
        }
        other => panic!("unexpected refusal: {other}"),
    }

    let silent_member = &bft_member_keys()[3];
    let refusal = bft_bundle_from(bft_template(), &[0, 1, 2], silent_member)
        .expect_err("a member that did not vote may not aggregate the quorum");
    match refusal {
        VerificationError::ConsensusEvidence(detail) => {
            assert!(detail.contains("did not vote in"), "{detail}");
        }
        other => panic!("unexpected refusal: {other}"),
    }
}

#[test]
fn votes_do_not_transfer_between_checkpoints_or_views() {
    let keys = bft_member_keys();
    let first = prepare_checkpoint(bft_template(), "bft_consensus").expect("prepares");
    let stale = first.vote_message().expect("vote message").to_vec();

    let mut other_batch = bft_template();
    other_batch["operations"][0]["body"] = json!({ "op": "set", "key": "other" });
    let second = prepare_checkpoint(other_batch, "bft_consensus").expect("prepares");
    assert_ne!(second.vote_message().expect("vote message"), stale.as_slice());
    let votes = (0..3_usize)
        .map(|index| BftVote {
            member_ref: format!("node://acme/aft/{index}"),
            signature: hex::encode(keys[index].sign(&stale).expect("signature").to_bytes()),
        })
        .collect::<Vec<_>>();
    assert!(
        finalize_bft_consensus(second, &votes, "key://acme/finality/1", &keys[0]).is_err(),
        "votes cast over one checkpoint must not finalize another"
    );
}

#[test]
fn consensus_evidence_is_bound_to_its_variant_in_both_directions() {
    let mut single = fixture(
        "../../docs/architecture/_meta/schemas/fixtures/receipt-proof-bundle-v2/positive-offline-single-authority.json",
    );
    single["checkpoint"]["finality_certificate"]["consensus_evidence"] =
        bft_template()["checkpoint"]["finality_certificate"]["consensus_evidence"].clone();
    let signing_key = Ed25519PrivateKey::from_bytes(&[7_u8; 32]).expect("test key");
    assert!(matches!(
        emit_single_authority(single, "key://acme/finality/1", &signing_key),
        Err(VerificationError::ConsensusEvidence(_))
    ));

    let mut bft = bft_template();
    bft["checkpoint"]["finality_certificate"]
        .as_object_mut()
        .expect("certificate object")
        .remove("consensus_evidence");
    assert!(matches!(
        prepare_checkpoint(bft, "bft_consensus"),
        Err(VerificationError::ConsensusEvidence(_))
    ));
}

#[test]
fn a_single_authority_certificate_preimage_gains_no_field() {
    // The compatibility claim, stated as a test: adding a variant-conditional
    // field must not change what a `single_authority_v1` certificate signs, so
    // its key set is pinned to the exact registered v1 field names.
    let bundle = signed_bundle();
    let certificate = &bundle["checkpoint"]["finality_certificate"];
    let names = certificate
        .as_object()
        .expect("certificate object")
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    assert_eq!(
        names,
        BTreeSet::from([
            "authority_epoch",
            "authority_revocation_epoch",
            "body_hash",
            "certificate_domain",
            "certificate_id",
            "certificate_variant",
            "checkpoint_hash",
            "claimed_axes",
            "domain_id",
            "issuer_key_id",
            "issuer_public_key",
            "operation_range",
            "profile",
            "profile_contract_version",
            "receipt_range",
            "schema_version",
            "signature",
            "signature_suite",
            "verifier_contract_hash",
            "verifier_contract_ref",
        ]),
    );
}

#[test]
fn profile_labels_resolve_before_admission_and_never_reach_the_wire() {
    for member in [
        "single_authority",
        "replicated_single_authority",
        "threshold_authority",
        "bft_consensus",
        "external_chain_finality",
    ] {
        assert_eq!(resolve_profile_label(member), Ok(member));
    }
    assert_eq!(resolve_profile_label("aft"), Ok("bft_consensus"));
    assert_eq!(
        resolve_profile_label("replicated_cft"),
        Ok("replicated_single_authority")
    );
    assert_eq!(
        resolve_profile_label("external_finality"),
        Ok("external_chain_finality")
    );
    assert!(matches!(
        resolve_profile_label("witnessed_threshold"),
        Err(VerificationError::AmbiguousProfileLabel { .. })
    ));
    assert!(matches!(
        resolve_profile_label("bft"),
        Err(VerificationError::UnknownProfileLabel(_))
    ));

    // The label resolves at the API boundary...
    assert!(bft_bundle_from(bft_template(), &[0, 1, 2], &bft_member_keys()[0]).is_ok());
    let prepared =
        prepare_checkpoint(bft_template(), "aft").expect("alias resolves before admission");
    assert_eq!(prepared.profile(), "bft_consensus");

    // ...but a label written on the wire is never admitted as a member.
    let mut aliased = bft_template();
    aliased["checkpoint"]["profile"] = Value::String("aft".into());
    assert!(matches!(
        prepare_checkpoint(aliased, "aft"),
        Err(VerificationError::UnsupportedProfile { .. })
    ));

    // A resolved member that disagrees with the wire refuses rather than
    // rewriting the wire to match the caller.
    let single = fixture(
        "../../docs/architecture/_meta/schemas/fixtures/receipt-proof-bundle-v2/positive-offline-single-authority.json",
    );
    assert!(matches!(
        prepare_checkpoint(single, "aft"),
        Err(VerificationError::UnsupportedProfile { .. })
    ));
}

#[test]
fn the_profile_does_not_decide_durability() {
    // Canon: the profile member names the ordering/finality rule and decides
    // nothing else. A weaker durability class is a separate declaration, so the
    // verifier must neither require nor infer `quorum_replicated` from BFT.
    let mut template = bft_template();
    template["checkpoint"]["durability_class"] = Value::String("buffered".into());
    let bundle = bft_bundle_from(template, &[0, 1, 2], &bft_member_keys()[0])
        .expect("durability is declared separately, not inferred from the profile");
    assert!(verify_bundle(&bundle).is_ok());
}

#[test]
fn membership_may_not_move_inside_one_authority_epoch() {
    let first = signed_bft_bundle();
    let successor = |patch: &dyn Fn(&mut Value)| -> Value {
        let mut next = bft_template();
        next["bundle_id"] = Value::String("proof://acme/bft/2".into());
        next["checkpoint"]["checkpoint_id"] =
            Value::String("receipt-checkpoint://acme/bft/2".into());
        next["checkpoint"]["finality_certificate"]["certificate_id"] =
            Value::String("finality-certificate://acme/bft/2".into());
        next["checkpoint"]["availability_manifest"]["manifest_id"] =
            Value::String("availability-manifest://acme/bft/2".into());
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
        let resulting_head = next["resulting_state_entries"][0]["value_hash"].clone();
        let previous_head = first["checkpoint"]["conflict_authority_binding"]["touched_objects"][0]
            ["resulting_head"]
            .clone();
        let touched = &mut next["checkpoint"]["conflict_authority_binding"]["touched_objects"][0];
        touched["previous_version"] = json!(1);
        touched["resulting_version"] = json!(2);
        touched["previous_head"] = previous_head;
        touched["resulting_head"] = resulting_head;
        patch(&mut next);
        next
    };

    // A new view under the same membership continues the history.
    let advanced = successor(&|next: &mut Value| {
        next["checkpoint"]["finality_certificate"]["consensus_evidence"]["view"] = json!(1);
    });
    let advanced = bft_bundle_from(advanced, &[0, 1, 2], &bft_member_keys()[0])
        .expect("a view change under one membership is ordinary");
    assert!(verify_bundle(&advanced).is_ok());

    // A membership change inside one authority epoch is not.
    let reconfigured = successor(&|next: &mut Value| {
        next["checkpoint"]["finality_certificate"]["consensus_evidence"]["membership_epoch"] =
            json!(2);
    });
    assert!(
        bft_bundle_from(reconfigured, &[0, 1, 2], &bft_member_keys()[0]).is_err(),
        "an unadmitted membership change must not ride an ordinary checkpoint"
    );
}

#[test]
fn checkpoint_state_version_must_advance_exactly_once() {
    let mut template = fixture(
        "../../docs/architecture/_meta/schemas/fixtures/receipt-proof-bundle-v2/positive-offline-single-authority.json",
    );
    template["checkpoint"]["resulting_state_commitment"]["version"] = json!(2);
    let signing_key = Ed25519PrivateKey::from_bytes(&[7_u8; 32]).expect("test key");
    assert!(emit_single_authority(template, "key://acme/finality/1", &signing_key).is_err());
}
