use super::*;
use ioi_api::chain::BlockExecutionReceipt;
use ioi_api::crypto::SigningKeyPair;
use ioi_crypto::security::SecurityLevel;
use ioi_crypto::sign::dilithium::MldsaScheme;
use ioi_types::app::{
    aft_async_canonical_qc_reference, aft_async_proposal_payload_hash,
    canonical_validator_set_hash, AccountId, ActiveKeyRecord, AftAsyncBatchProposalV1,
    AftAsyncDecisionVoteV1, AftAsyncExecutedBlockCertificateV1, AftAsyncExecutedBlockDecisionV1,
    AftAsyncExecutedBlockVoteV1, AftAsyncGeometryV1, AftAsyncInstanceV1,
    AftAsyncOrderingCertificateV1, AftAsyncOrderingDecisionV1,
    AftAsyncProposalAvailabilityCertificateV1, AftAsyncProposalAvailabilityVoteV1,
    AftAsyncProposalDescriptorV1, AftAsyncSelectedBatchWitnessV1,
    AftAsyncSelectedProposalWitnessV1, AftAsyncTranscriptSummaryV1, AftFallbackScopeV1,
    AftFallbackTriggerCertificateV1, AftTimeoutCertificateV1, AftTimeoutVoteV1,
    ApplicationTransaction, FallbackStartCertificateV1, SignHeader, SignatureProof, ValidatorSetV1,
    ValidatorV1, AFT_ASYNC_PROTOCOL_VERSION_V1, AFT_ASYNC_SCHEMA_VERSION_V1,
};
use ioi_types::config::RuntimeFinalityProfile;
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
        Err(VerificationError::UnsupportedAxis(
            "non_equivocation".into()
        ))
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
    assert_ne!(
        second.vote_message().expect("vote message"),
        stale.as_slice()
    );
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
        next["checkpoint"]["previous_checkpoint_ref"] =
            first["checkpoint"]["checkpoint_id"].clone();
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

// ---------------------------------------------------------------------------
// Native AFT bridge: imported QuorumCertificate evidence
// ---------------------------------------------------------------------------

use ioi_types::app::StateRoot;

const NATIVE_TEMPLATE: &str = "tests/fixtures/template-offline-native-aft.json";
const NATIVE_HEIGHT: u64 = 7;
const NATIVE_VIEW: u64 = 0;

fn native_key_bytes(key: &Ed25519PrivateKey) -> [u8; 32] {
    key.public_key()
        .expect("member public key")
        .to_bytes()
        .as_slice()
        .try_into()
        .expect("ed25519 public keys are 32 bytes")
}

fn native_members() -> Vec<NativeAftMember> {
    bft_member_keys()
        .iter()
        .enumerate()
        .map(|(index, key)| NativeAftMember {
            member_ref: format!("node://acme/aft/{index}"),
            signature_suite: SignatureSuite::ED25519,
            public_key: native_key_bytes(key).to_vec(),
        })
        .collect()
}

fn native_account(member: &NativeAftMember) -> AccountId {
    AccountId(
        account_id_from_key_material(member.signature_suite, &member.public_key)
            .expect("account id derives"),
    )
}

/// A block header shaped like one the live path produces. Only the fields the
/// bridge actually reads carry meaning: height, view, and the committed
/// `validator_set` that the declared membership has to derive onto.
fn native_header(members: &[NativeAftMember], height: u64, view: u64) -> BlockHeader {
    BlockHeader {
        height,
        view,
        parent_hash: [1_u8; 32],
        parent_state_root: StateRoot(vec![2_u8; 32]),
        state_root: StateRoot(vec![3_u8; 32]),
        transactions_root: vec![4_u8; 32],
        timestamp: 1_700_000_000,
        timestamp_ms: 1_700_000_000_000,
        gas_used: 0,
        validator_set: members
            .iter()
            .map(|member| native_account(member).0.to_vec())
            .collect(),
        producer_account_id: native_account(&members[0]),
        producer_key_suite: SignatureSuite::ED25519,
        producer_pubkey_hash: [10_u8; 32],
        producer_pubkey: members[0].public_key.clone(),
        oracle_counter: 0,
        oracle_trace_hash: [0_u8; 32],
        guardian_certificate: None,
        sealed_finality_proof: None,
        canonical_order_certificate: None,
        timeout_certificate: None,
        aft_timeout_certificate: None,
        parent_qc: QuorumCertificate::default(),
        previous_canonical_collapse_commitment_hash: [0_u8; 32],
        canonical_collapse_extension_certificate: None,
        publication_frontier: None,
        signature: Vec::new(),
    }
}

struct NativeFixture {
    finalized: NativeAftFinalizedBlock,
    header_bytes: Vec<u8>,
    block_hash: [u8; 32],
}

/// Build a finalized block plus the certificate the live path would have formed
/// over it. `voters` names which members signed; every signature is a real
/// Ed25519 signature over the real native preimage.
fn native_fixture(voters: &[usize], height: u64, view: u64) -> NativeFixture {
    let keys = bft_member_keys();
    let members = native_members();
    let header = native_header(&members, height, view);
    let header_bytes = to_bytes_canonical(&header).expect("header encodes");
    let block_hash: [u8; 32] = header
        .hash()
        .expect("header hashes")
        .as_slice()
        .try_into()
        .expect("32-byte digest");
    let message = native_aft_vote_message(height, view, &block_hash).expect("vote message");
    let signatures = voters
        .iter()
        .map(|index| {
            (
                native_account(&members[*index]),
                keys[*index]
                    .sign(&message)
                    .expect("member signs")
                    .to_bytes()
                    .to_vec(),
            )
        })
        .collect();
    NativeFixture {
        finalized: NativeAftFinalizedBlock {
            block_header_bytes: header_bytes.clone(),
            quorum_certificate: QuorumCertificate {
                height,
                view,
                block_hash,
                signatures,
                aggregated_signature: Vec::new(),
                signers_bitfield: Vec::new(),
            },
            members,
            membership_ref: "node-membership://acme/aft/1".into(),
            membership_epoch: 1,
            consensus_protocol_ref: "protocol://ioi/aft/v1".into(),
            byzantine_fault_tolerance: 1,
        },
        header_bytes,
        block_hash,
    }
}

fn native_effect_transaction(code: u8) -> ChainTransaction {
    ChainTransaction::Application(ApplicationTransaction::DeployContract {
        header: SignHeader::default(),
        code: vec![code],
        signature_proof: SignatureProof::default(),
    })
}

fn native_effect_fixture(
    transactions: Vec<ChainTransaction>,
    first_sequence: u64,
) -> (NativeFixture, Vec<u8>, Vec<NativeAftOperationBinding>) {
    let keys = bft_member_keys();
    let members = native_members();
    let mut header = native_header(&members, NATIVE_HEIGHT, NATIVE_VIEW);
    header.transactions_root =
        canonical_transactions_root(&transactions).expect("transaction root derives");
    let header_bytes = to_bytes_canonical(&header).expect("header encodes");
    let block_hash: [u8; 32] = header
        .hash()
        .expect("header hashes")
        .as_slice()
        .try_into()
        .expect("32-byte digest");
    let message =
        native_aft_vote_message(NATIVE_HEIGHT, NATIVE_VIEW, &block_hash).expect("vote message");
    let signatures = [0_usize, 1, 2]
        .iter()
        .map(|index| {
            (
                native_account(&members[*index]),
                keys[*index]
                    .sign(&message)
                    .expect("member signs")
                    .to_bytes()
                    .to_vec(),
            )
        })
        .collect();
    let bindings = transactions
        .iter()
        .enumerate()
        .map(|(index, transaction)| NativeAftOperationBinding {
            operation_sequence: first_sequence + index as u64,
            transaction_index: index as u64,
            transaction_bytes: to_bytes_canonical(transaction).expect("transaction encodes"),
        })
        .collect();
    let full_block_bytes = to_bytes_canonical(&Block {
        header,
        transactions,
    })
    .expect("full block encodes");
    (
        NativeFixture {
            finalized: NativeAftFinalizedBlock {
                block_header_bytes: header_bytes.clone(),
                quorum_certificate: QuorumCertificate {
                    height: NATIVE_HEIGHT,
                    view: NATIVE_VIEW,
                    block_hash,
                    signatures,
                    aggregated_signature: Vec::new(),
                    signers_bitfield: Vec::new(),
                },
                members,
                membership_ref: "node-membership://acme/aft/1".into(),
                membership_epoch: 1,
                consensus_protocol_ref: "protocol://ioi/aft/v1".into(),
                byzantine_fault_tolerance: 1,
            },
            header_bytes,
            block_hash,
        },
        full_block_bytes,
        bindings,
    )
}

/// The template with its availability declaration filled in from the real
/// header bytes, the way a runtime would publish the block before certifying.
fn native_template(header_bytes: &[u8]) -> Value {
    let mut template = fixture(NATIVE_TEMPLATE);
    template["checkpoint"]["availability_manifest"]["payloads"][0]["payload_hash"] =
        Value::String(hash_bytes(header_bytes));
    template["checkpoint"]["availability_manifest"]["payloads"][0]["byte_length"] =
        json!(header_bytes.len());
    template["availability_payloads"][0]["payload_base64"] =
        Value::String(BASE64.encode(header_bytes));
    template
}

fn native_issuer() -> Ed25519PrivateKey {
    Ed25519PrivateKey::from_bytes(&[7_u8; 32]).expect("issuer key")
}

fn native_bundle_from(fixture: &NativeFixture) -> Result<Value, VerificationError> {
    emit_native_aft_consensus(
        native_template(&fixture.header_bytes),
        &fixture.finalized,
        "key://acme/finality/1",
        &native_issuer(),
    )
}

fn signed_native_bundle() -> Value {
    native_bundle_from(&native_fixture(&[0, 1, 2], NATIVE_HEIGHT, NATIVE_VIEW))
        .expect("native fixture emits and self-verifies")
}

/// Mutate the certificate and then **re-issue it with the real issuer key**, so
/// the outer signature is valid again. A refusal therefore proves the quorum
/// rule held on its own, rather than the issuer signature catching the edit.
/// This is the threat model that matters: the issuer is not the safety source.
fn native_reissued(mutate: impl FnOnce(&mut Value)) -> Value {
    let mut bundle = signed_native_bundle();
    mutate(&mut bundle);
    let issuer = native_issuer();
    let certificate = bundle
        .pointer_mut("/checkpoint/finality_certificate")
        .expect("certificate");
    let body = hash_value(&without(certificate, &["body_hash", "signature"]).expect("preimage"))
        .expect("body hash");
    set_text(certificate, "body_hash", body.clone()).expect("rewrite body hash");
    let message = format!("ioi.finality-certificate.v1\0{body}");
    let signature = issuer.sign(message.as_bytes()).expect("issuer re-signs");
    set_text(certificate, "signature", hex::encode(signature.to_bytes()))
        .expect("rewrite signature");
    let outer =
        hash_value(&without(&bundle, &["bundle_hash"]).expect("outer preimage")).expect("outer");
    set_text(&mut bundle, "bundle_hash", outer).expect("rewrite bundle hash");
    bundle
}

#[test]
fn native_aft_quorum_verifies_offline_and_reports_its_binding() {
    let bundle = signed_native_bundle();
    let claim = verify_bundle(&bundle).expect("native bundle verifies");
    assert_eq!(claim.profile, "bft_consensus");
    assert_eq!(claim.certificate_variant, "bft_consensus_aft_v1");
    let quorum = claim.quorum.expect("native evidence claims a quorum");
    assert_eq!(quorum.vote_binding, NATIVE_AFT_VOTE_BINDING);
    assert_eq!(quorum.total_voting_members, 4);
    assert_eq!(quorum.quorum_threshold, 3);
    assert_eq!(quorum.distinct_member_signatures_verified, 3);

    let block = quorum
        .certified_block
        .expect("native evidence names a block");
    assert_eq!(block.block_height, NATIVE_HEIGHT);
    assert_eq!(block.block_view, NATIVE_VIEW);
    assert!(
        block.block_bytes_reverified,
        "the supplied header bytes must be re-hashed, not trusted"
    );
    // The load-bearing nonclaim: a verified quorum certifies the block, never
    // this checkpoint's effect.
    assert!(!block.effect_committed_in_block);
}

#[test]
fn full_native_block_binds_every_operation_and_both_state_roots() {
    let (fixture, block_bytes, bindings) = native_effect_fixture(
        vec![native_effect_transaction(1), native_effect_transaction(2)],
        41,
    );
    let verified = verify_native_aft_full_block_effects(
        &fixture.finalized,
        &block_bytes,
        &bindings,
        &[2_u8; 32],
        &[3_u8; 32],
    )
    .expect("full block association verifies");
    assert_eq!(verified.block_height, NATIVE_HEIGHT);
    assert_eq!(verified.block_view, NATIVE_VIEW);
    assert_eq!(verified.transaction_count, 2);
    assert_eq!(verified.first_operation_sequence, Some(41));
    assert_eq!(verified.last_operation_sequence, Some(42));
    assert!(verified.full_block_bytes_reverified);
    assert!(verified.effect_committed_in_block);
    assert!(
        !verified.receipts_committed_in_block,
        "the current header has no receipt commitment"
    );
}

#[test]
fn full_native_block_effect_substitutions_fail_closed() {
    let (fixture, block_bytes, bindings) = native_effect_fixture(
        vec![native_effect_transaction(1), native_effect_transaction(2)],
        41,
    );

    let mut changed_bytes = bindings.clone();
    changed_bytes[0].transaction_bytes.push(0);
    assert!(verify_native_aft_full_block_effects(
        &fixture.finalized,
        &block_bytes,
        &changed_bytes,
        &[2_u8; 32],
        &[3_u8; 32],
    )
    .is_err());

    let mut reordered = bindings.clone();
    reordered.swap(0, 1);
    assert!(verify_native_aft_full_block_effects(
        &fixture.finalized,
        &block_bytes,
        &reordered,
        &[2_u8; 32],
        &[3_u8; 32],
    )
    .is_err());

    let mut sequence_gap = bindings.clone();
    sequence_gap[1].operation_sequence += 1;
    assert!(verify_native_aft_full_block_effects(
        &fixture.finalized,
        &block_bytes,
        &sequence_gap,
        &[2_u8; 32],
        &[3_u8; 32],
    )
    .is_err());

    assert!(verify_native_aft_full_block_effects(
        &fixture.finalized,
        &block_bytes,
        &bindings,
        &[9_u8; 32],
        &[3_u8; 32],
    )
    .is_err());
    assert!(verify_native_aft_full_block_effects(
        &fixture.finalized,
        &block_bytes,
        &bindings,
        &[2_u8; 32],
        &[9_u8; 32],
    )
    .is_err());

    let mut torn = block_bytes.clone();
    torn.pop();
    assert!(verify_native_aft_full_block_effects(
        &fixture.finalized,
        &torn,
        &bindings,
        &[2_u8; 32],
        &[3_u8; 32],
    )
    .is_err());

    let short = &bindings[..1];
    assert!(verify_native_aft_full_block_effects(
        &fixture.finalized,
        &block_bytes,
        short,
        &[2_u8; 32],
        &[3_u8; 32],
    )
    .is_err());
}

#[test]
fn the_checkpoint_round_and_the_native_binding_are_never_interchangeable() {
    // The non-runtime round still works, and still reports itself as such.
    let round = verify_bundle(&signed_bft_bundle()).expect("checkpoint round verifies");
    assert_eq!(
        round.quorum.expect("quorum").vote_binding,
        CHECKPOINT_VOTE_BINDING
    );

    // A native-bound template may not be finalized through the fresh-round API,
    // which would install signatures over the wrong message entirely.
    let fixture = native_fixture(&[0, 1, 2], NATIVE_HEIGHT, NATIVE_VIEW);
    let mut template = native_template(&fixture.header_bytes);
    template["checkpoint"]["finality_certificate"]["consensus_evidence"]["votes"] = json!([]);
    let prepared = prepare_checkpoint(template, "bft_consensus").expect("prepares");
    assert!(
        prepared.vote_message().is_none(),
        "a native template must offer no message for a second signature round"
    );
    assert_eq!(prepared.vote_binding(), Some(NATIVE_AFT_VOTE_BINDING));
    assert!(matches!(
        finalize_bft_consensus(prepared, &[], "key://acme/finality/1", &native_issuer()),
        Err(VerificationError::ConsensusEvidence(_))
    ));
}

#[test]
fn native_votes_are_verified_against_the_exact_native_preimage() {
    // The signed bytes are SCALE over `(height, view, block_hash)` — reproduced
    // here independently of the emitter to pin the wire format itself.
    let fixture = native_fixture(&[0, 1, 2], NATIVE_HEIGHT, NATIVE_VIEW);
    let message =
        native_aft_vote_message(NATIVE_HEIGHT, NATIVE_VIEW, &fixture.block_hash).expect("message");
    let mut expected = Vec::new();
    expected.extend_from_slice(&NATIVE_HEIGHT.to_le_bytes());
    expected.extend_from_slice(&NATIVE_VIEW.to_le_bytes());
    expected.extend_from_slice(&fixture.block_hash);
    assert_eq!(
        message, expected,
        "native preimage must be 8+8+32 SCALE bytes"
    );

    // A signature over anything else — here the same tuple at another view —
    // must not verify, which is what stops a vote being re-aimed at a decision
    // its signer never made.
    let other = native_aft_vote_message(NATIVE_HEIGHT, NATIVE_VIEW + 1, &fixture.block_hash)
        .expect("message");
    assert_ne!(message, other);
}

/// Height, view, and block-hash substitutions all break the preimage the votes
/// signed, so each must refuse even though the issuer re-signs the edit.
#[test]
fn certified_block_identity_substitutions_fail_closed() {
    for (label, pointer, replacement) in [
        (
            "height",
            "/checkpoint/finality_certificate/consensus_evidence/certified_block/block_height",
            json!(NATIVE_HEIGHT + 1),
        ),
        (
            "view",
            "/checkpoint/finality_certificate/consensus_evidence/view",
            json!(NATIVE_VIEW + 1),
        ),
        (
            "block hash",
            "/checkpoint/finality_certificate/consensus_evidence/certified_block/block_hash",
            Value::String(format!("sha256:{}", "ab".repeat(32))),
        ),
    ] {
        let bundle = native_reissued(|bundle| {
            *bundle.pointer_mut(pointer).expect("pointer exists") = replacement;
        });
        assert!(
            verify_bundle(&bundle).is_err(),
            "{label} substitution unexpectedly verified"
        );
    }
}

#[test]
fn substituted_vote_bytes_and_members_fail_closed() {
    // A tampered signature.
    let forged = native_reissued(|bundle| {
        bundle["checkpoint"]["finality_certificate"]["consensus_evidence"]["votes"][0]
            ["signature"] = Value::String("00".repeat(64));
    });
    assert!(matches!(
        verify_bundle(&forged),
        Err(VerificationError::ConsensusEvidence(_) | VerificationError::Crypto(_))
    ));

    // A vote reassigned to a member who did not cast it: the signature no
    // longer verifies under that member's key.
    let reassigned = native_reissued(|bundle| {
        bundle["checkpoint"]["finality_certificate"]["consensus_evidence"]["votes"][0]
            ["member_ref"] = Value::String("node://acme/aft/3".into());
    });
    assert!(matches!(
        verify_bundle(&reassigned),
        Err(VerificationError::ConsensusEvidence(_))
    ));

    // A member key swapped for one that was never in the block's committed
    // validator set.
    let outsider = Ed25519PrivateKey::from_bytes(&[99_u8; 32]).expect("outsider");
    let swapped = native_reissued(|bundle| {
        bundle["checkpoint"]["finality_certificate"]["consensus_evidence"]["members"][3]
            ["public_key"] = Value::String(hex::encode(native_key_bytes(&outsider)));
    });
    assert!(
        verify_bundle(&swapped).is_err(),
        "a key outside the certified block's validator set must refuse"
    );
}

#[test]
fn a_quorum_certificate_from_outside_the_committed_validator_set_is_refused() {
    // The engine forms a QC without checking membership at all, so this is the
    // exact class of certificate the bridge has to catch on its own.
    let mut fixture = native_fixture(&[0, 1, 2], NATIVE_HEIGHT, NATIVE_VIEW);
    let outsider = Ed25519PrivateKey::from_bytes(&[123_u8; 32]).expect("outsider");
    let message =
        native_aft_vote_message(NATIVE_HEIGHT, NATIVE_VIEW, &fixture.block_hash).expect("message");
    let account = AccountId(
        account_id_from_key_material(SignatureSuite::ED25519, &native_key_bytes(&outsider))
            .expect("account"),
    );
    fixture.finalized.quorum_certificate.signatures[2] = (
        account,
        outsider.sign(&message).expect("sign").to_bytes().to_vec(),
    );
    let refusal = native_bundle_from(&fixture).expect_err("undeclared signer must refuse");
    assert!(matches!(refusal, VerificationError::ConsensusEvidence(_)));
}

#[test]
fn weight_quorum_and_fault_model_substitutions_fail_closed() {
    // Below the threshold: two of four is not a quorum.
    let short = native_fixture(&[0, 1], NATIVE_HEIGHT, NATIVE_VIEW);
    assert!(
        native_bundle_from(&short).is_err(),
        "two of four members is not a byzantine quorum"
    );

    // A relabelled fault model.
    let unfaulted = native_reissued(|bundle| {
        bundle["checkpoint"]["finality_certificate"]["consensus_evidence"]["fault_model"] =
            Value::String("crash".into());
    });
    assert!(verify_bundle(&unfaulted).is_err());

    // A dropped synchrony declaration.
    let asynchronous = native_reissued(|bundle| {
        bundle["checkpoint"]["finality_certificate"]["consensus_evidence"]["synchrony_model"] =
            Value::String("asynchronous".into());
    });
    assert!(verify_bundle(&asynchronous).is_err());

    // A threshold lowered to a simple majority is a guardian-majority quorum
    // wearing a byzantine label, and must refuse even with the votes present.
    let majority = native_reissued(|bundle| {
        bundle["checkpoint"]["finality_certificate"]["consensus_evidence"]["quorum_threshold"] =
            json!(2);
    });
    assert!(verify_bundle(&majority).is_err());

    // `2f + 1` is not sufficient when `n > 3f + 1`: five members tolerating one
    // fault need four, because two three-member quorums can meet only at the
    // faulty one.
    let understated = native_reissued(|bundle| {
        let evidence = &mut bundle["checkpoint"]["finality_certificate"]["consensus_evidence"];
        evidence["total_voting_members"] = json!(5);
        evidence["quorum_threshold"] = json!(3);
    });
    assert!(matches!(
        verify_bundle(&understated),
        Err(VerificationError::ConsensusEvidence(_))
    ));
}

#[test]
fn profile_and_variant_substitutions_fail_closed() {
    let mut relabelled = signed_native_bundle();
    relabelled["checkpoint"]["profile"] = Value::String("single_authority".into());
    relabelled["checkpoint"]["finality_certificate"]["profile"] =
        Value::String("single_authority".into());
    assert!(matches!(
        verify_bundle(&relabelled),
        Err(VerificationError::UnsupportedProfile { .. })
    ));

    let mut variant = signed_native_bundle();
    variant["checkpoint"]["finality_certificate"]["certificate_variant"] =
        Value::String("single_authority_v1".into());
    // A non-BFT variant carrying consensus evidence refuses on the negation
    // rule the schema dialect cannot express.
    assert!(matches!(
        verify_bundle(&variant),
        Err(VerificationError::UnsupportedProfile { .. } | VerificationError::ConsensusEvidence(_))
    ));

    // A native binding may not shed its certified block, and a checkpoint round
    // may not acquire one.
    let unbound = native_reissued(|bundle| {
        let evidence = bundle["checkpoint"]["finality_certificate"]["consensus_evidence"]
            .as_object_mut()
            .expect("evidence object");
        evidence.remove("certified_block");
    });
    assert!(verify_bundle(&unbound).is_err());

    let mislabelled = native_reissued(|bundle| {
        bundle["checkpoint"]["finality_certificate"]["consensus_evidence"]["vote_binding"] =
            Value::String(CHECKPOINT_VOTE_BINDING.into());
    });
    assert!(matches!(
        verify_bundle(&mislabelled),
        Err(VerificationError::ConsensusEvidence(_))
    ));
}

#[test]
fn substituted_availability_block_bytes_fail_closed() {
    // Swapping the published header for another real header must refuse: the
    // block a verifier can retrieve has to be the block that was certified.
    let other = native_fixture(&[0, 1, 2], NATIVE_HEIGHT + 1, NATIVE_VIEW);
    let mut bundle = signed_native_bundle();
    bundle["availability_payloads"][0]["payload_base64"] =
        Value::String(BASE64.encode(&other.header_bytes));
    let outer =
        hash_value(&without(&bundle, &["bundle_hash"]).expect("outer preimage")).expect("outer");
    set_text(&mut bundle, "bundle_hash", outer).expect("rewrite bundle hash");
    assert!(verify_bundle(&bundle).is_err());

    // And a header the manifest never declared cannot be smuggled in by
    // rewriting the manifest hash alongside it.
    let mut swapped = native_reissued(|_| {});
    swapped["availability_payloads"][0]["payload_base64"] = Value::String(BASE64.encode([1_u8; 8]));
    let outer =
        hash_value(&without(&swapped, &["bundle_hash"]).expect("outer preimage")).expect("outer");
    set_text(&mut swapped, "bundle_hash", outer).expect("rewrite bundle hash");
    assert!(verify_bundle(&swapped).is_err());
}

#[test]
fn an_aggregated_bls_certificate_is_refused_rather_than_partially_counted() {
    // The aggregate fields are dead in the engine today. If one is ever
    // populated this bridge cannot check it, so it must refuse rather than
    // silently verify only the explicit list and report a full quorum.
    let mut fixture = native_fixture(&[0, 1, 2], NATIVE_HEIGHT, NATIVE_VIEW);
    fixture.finalized.quorum_certificate.aggregated_signature = vec![9_u8; 96];
    assert!(matches!(
        native_bundle_from(&fixture),
        Err(VerificationError::ConsensusEvidence(_))
    ));
}

#[test]
fn a_header_that_does_not_hash_to_the_certified_block_is_refused() {
    let mut fixture = native_fixture(&[0, 1, 2], NATIVE_HEIGHT, NATIVE_VIEW);
    // Keep the certificate, swap the header for a different real one.
    let other = native_fixture(&[0, 1, 2], NATIVE_HEIGHT, NATIVE_VIEW + 5);
    fixture.finalized.block_header_bytes = other.header_bytes.clone();
    assert!(matches!(
        emit_native_aft_consensus(
            native_template(&other.header_bytes),
            &fixture.finalized,
            "key://acme/finality/1",
            &native_issuer(),
        ),
        Err(VerificationError::ConsensusEvidence(_))
    ));
}

#[test]
fn a_block_committing_no_validator_set_binds_no_membership() {
    let members = native_members();
    let mut header = native_header(&members, NATIVE_HEIGHT, NATIVE_VIEW);
    header.validator_set = Vec::new();
    let header_bytes = to_bytes_canonical(&header).expect("encodes");
    let block_hash: [u8; 32] = header
        .hash()
        .expect("hashes")
        .as_slice()
        .try_into()
        .expect("32 bytes");
    let message =
        native_aft_vote_message(NATIVE_HEIGHT, NATIVE_VIEW, &block_hash).expect("message");
    let keys = bft_member_keys();
    let signatures = [0_usize, 1, 2]
        .iter()
        .map(|index| {
            (
                native_account(&members[*index]),
                keys[*index]
                    .sign(&message)
                    .expect("sign")
                    .to_bytes()
                    .to_vec(),
            )
        })
        .collect();
    let finalized = NativeAftFinalizedBlock {
        block_header_bytes: header_bytes.clone(),
        quorum_certificate: QuorumCertificate {
            height: NATIVE_HEIGHT,
            view: NATIVE_VIEW,
            block_hash,
            signatures,
            aggregated_signature: Vec::new(),
            signers_bitfield: Vec::new(),
        },
        members,
        membership_ref: "node-membership://acme/aft/1".into(),
        membership_epoch: 1,
        consensus_protocol_ref: "protocol://ioi/aft/v1".into(),
        byzantine_fault_tolerance: 1,
    };
    let refusal = emit_native_aft_consensus(
        native_template(&header_bytes),
        &finalized,
        "key://acme/finality/1",
        &native_issuer(),
    )
    .expect_err("an empty committed validator set pins nothing");
    assert!(matches!(refusal, VerificationError::ConsensusEvidence(_)));
}

const RUNTIME_TEST_HASH: &str =
    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn runtime_v3_bundle(profile: RuntimeFinalityProfile) -> Value {
    let transactions = vec![native_effect_transaction(11), native_effect_transaction(12)];
    let (fixture, block_bytes, _) = native_effect_fixture(transactions, 41);
    let block: Block<ChainTransaction> =
        from_bytes_canonical(&block_bytes).expect("runtime block decodes");
    let receipts: Vec<_> = block
        .transactions
        .iter()
        .enumerate()
        .map(|(index, transaction)| {
            BlockExecutionReceipt::for_success(
                block.header.height,
                index as u64,
                transaction.hash().expect("transaction hashes"),
                0,
                &[],
            )
        })
        .collect();
    let native_aft = match profile {
        RuntimeFinalityProfile::BftConsensusAftV1 => Some(&fixture.finalized),
        RuntimeFinalityProfile::SingleAuthorityV1 => None,
    };
    emit_runtime_bundle_v3(
        RuntimeBundleV3Input {
            bundle_id: "proof://acme/runtime/7",
            checkpoint_id: "receipt-checkpoint://acme/runtime/7",
            certificate_id: "finality-certificate://acme/runtime/7",
            availability_manifest_id: "availability-manifest://acme/runtime/7",
            block_payload_ref: "payload://acme/runtime/block/7",
            domain_id: "domain://acme/runtime",
            authority_epoch: 9,
            authority_revocation_epoch: 4,
            profile,
            profile_epoch: 3,
            writer_identity: "writer://acme/validator/1",
            fence_token: 17,
            operation_sequence_first: 41,
            receipt_sequence_first: 81,
            previous_checkpoint_ref: Some("receipt-checkpoint://acme/runtime/6"),
            previous_checkpoint_hash: Some(RUNTIME_TEST_HASH),
            authority_policy_root: RUNTIME_TEST_HASH,
            governance_policy_root: RUNTIME_TEST_HASH,
            availability_policy_root: RUNTIME_TEST_HASH,
            retention_policy_root: RUNTIME_TEST_HASH,
            location_ref: "agentgres://acme/runtime/block/7",
            failure_domain_ref: "failure-domain://acme/local-device",
            verifier_contract_hash: RUNTIME_TEST_HASH,
            issuer_key_id: "key://acme/finality/9",
            block: &block,
            receipts: &receipts,
            native_aft,
            hash_async: None,
        },
        &native_issuer(),
    )
    .expect("runtime v3 fixture emits and self-verifies")
}

fn runtime_v3_pq_bundle() -> Value {
    let scheme = MldsaScheme::new(SecurityLevel::Level2);
    let keys: Vec<_> = (0..4)
        .map(|_| scheme.generate_keypair().expect("ML-DSA-44 keypair"))
        .collect();
    let members: Vec<_> = keys
        .iter()
        .enumerate()
        .map(|(index, key)| NativeAftMember {
            member_ref: format!("node://acme/pq-aft/{index}"),
            signature_suite: SignatureSuite::ML_DSA_44,
            public_key: key.public_key().to_bytes(),
        })
        .collect();
    let transactions = vec![native_effect_transaction(77)];
    let mut header = native_header(&members, NATIVE_HEIGHT, NATIVE_VIEW);
    header.producer_key_suite = SignatureSuite::ML_DSA_44;
    header.producer_pubkey = members[0].public_key.clone();
    header.transactions_root =
        canonical_transactions_root(&transactions).expect("transaction root derives");
    let block = Block {
        header,
        transactions,
    };
    let block_hash: [u8; 32] = block
        .header
        .hash()
        .expect("header hashes")
        .as_slice()
        .try_into()
        .expect("32-byte digest");
    let message = native_aft_vote_message(NATIVE_HEIGHT, NATIVE_VIEW, &block_hash)
        .expect("native vote message");
    let signatures = [0_usize, 1, 2]
        .into_iter()
        .map(|index| {
            (
                native_account(&members[index]),
                keys[index]
                    .sign(&message)
                    .expect("PQ member signs")
                    .to_bytes(),
            )
        })
        .collect();
    let finalized = NativeAftFinalizedBlock {
        block_header_bytes: to_bytes_canonical(&block.header).expect("header encodes"),
        quorum_certificate: QuorumCertificate {
            height: NATIVE_HEIGHT,
            view: NATIVE_VIEW,
            block_hash,
            signatures,
            aggregated_signature: Vec::new(),
            signers_bitfield: Vec::new(),
        },
        members,
        membership_ref: "node-membership://acme/pq-aft/1".into(),
        membership_epoch: 1,
        consensus_protocol_ref: "protocol://ioi/aft/pq-optimistic/v1".into(),
        byzantine_fault_tolerance: 1,
    };
    let receipts = vec![BlockExecutionReceipt::for_success(
        block.header.height,
        0,
        block.transactions[0].hash().expect("transaction hashes"),
        0,
        &[],
    )];
    emit_runtime_bundle_v3(
        RuntimeBundleV3Input {
            bundle_id: "proof://acme/runtime/pq/7",
            checkpoint_id: "receipt-checkpoint://acme/runtime/pq/7",
            certificate_id: "finality-certificate://acme/runtime/pq/7",
            availability_manifest_id: "availability-manifest://acme/runtime/pq/7",
            block_payload_ref: "payload://acme/runtime/pq/block/7",
            domain_id: "domain://acme/runtime/pq",
            authority_epoch: 9,
            authority_revocation_epoch: 4,
            profile: RuntimeFinalityProfile::BftConsensusAftV1,
            profile_epoch: 3,
            writer_identity: "writer://acme/validator/1",
            fence_token: 17,
            operation_sequence_first: 41,
            receipt_sequence_first: 81,
            previous_checkpoint_ref: None,
            previous_checkpoint_hash: None,
            authority_policy_root: RUNTIME_TEST_HASH,
            governance_policy_root: RUNTIME_TEST_HASH,
            availability_policy_root: RUNTIME_TEST_HASH,
            retention_policy_root: RUNTIME_TEST_HASH,
            location_ref: "agentgres://acme/runtime/pq/block/7",
            failure_domain_ref: "failure-domain://acme/local-device",
            verifier_contract_hash: RUNTIME_TEST_HASH,
            issuer_key_id: "key://acme/finality/9",
            block: &block,
            receipts: &receipts,
            native_aft: Some(&finalized),
            hash_async: None,
        },
        &native_issuer(),
    )
    .expect("PQ runtime v3 fixture emits and self-verifies")
}

pub(crate) fn runtime_v3_hash_async_bundle() -> Value {
    runtime_v3_hash_async_bundle_for_subject(false, false).0
}

fn runtime_v3_hash_async_parent_bundle() -> Value {
    runtime_v3_hash_async_bundle_for_subject(true, false).0
}

fn runtime_v3_hash_async_pq_issuer_bundle() -> Value {
    runtime_v3_hash_async_bundle_for_subject(false, true).0
}

pub(crate) fn runtime_v3_hash_async_pq_bundle_with_keys() -> (Value, Vec<(AccountId, MldsaKeyPair)>)
{
    runtime_v3_hash_async_bundle_for_subject(false, true)
}

fn runtime_v3_hash_async_bundle_for_subject(
    admit_parent: bool,
    pq_issuer: bool,
) -> (Value, Vec<(AccountId, MldsaKeyPair)>) {
    let scheme = MldsaScheme::new(SecurityLevel::Level2);
    let mut keyed = (0..4)
        .map(|_| {
            let key = scheme.generate_keypair().expect("ML-DSA-44 keypair");
            let raw = key.public_key().to_bytes();
            let account = AccountId(
                account_id_from_key_material(SignatureSuite::ML_DSA_44, &raw)
                    .expect("account derives"),
            );
            (account, key, raw)
        })
        .collect::<Vec<_>>();
    keyed.sort_by_key(|(account, _, _)| *account);
    let members = keyed
        .iter()
        .enumerate()
        .map(|(index, (_, _, raw))| NativeAftMember {
            member_ref: format!("node://acme/hash-async/{index}"),
            signature_suite: SignatureSuite::ML_DSA_44,
            public_key: raw.clone(),
        })
        .collect::<Vec<_>>();
    let set = ValidatorSetV1 {
        effective_from_height: 1,
        total_weight: 4,
        validators: keyed
            .iter()
            .map(|(account, _, raw)| ValidatorV1 {
                account_id: *account,
                weight: 1,
                consensus_key: ActiveKeyRecord {
                    suite: SignatureSuite::ML_DSA_44,
                    public_key_hash: account_id_from_key_material(SignatureSuite::ML_DSA_44, raw)
                        .expect("key hash derives"),
                    since_height: 1,
                },
            })
            .collect(),
    };
    let scope = AftFallbackScopeV1 {
        network_id: [0x31; 32],
        configuration_hash: canonical_validator_set_hash(&set).expect("set hashes"),
        epoch: 1,
    };
    let mut parent_header = native_header(&members, NATIVE_HEIGHT - 1, 0);
    parent_header.transactions_root = canonical_transactions_root(&[]).unwrap();
    let parent_block = Block {
        header: parent_header,
        transactions: Vec::new(),
    };
    let parent_hash: [u8; 32] = parent_block
        .header
        .hash()
        .unwrap()
        .as_slice()
        .try_into()
        .unwrap();
    let mut high_qc = QuorumCertificate {
        height: NATIVE_HEIGHT - 1,
        view: 0,
        block_hash: parent_hash,
        signatures: Vec::new(),
        aggregated_signature: Vec::new(),
        signers_bitfield: Vec::new(),
    };
    let high_qc_message =
        native_aft_vote_message(high_qc.height, high_qc.view, &high_qc.block_hash)
            .expect("high-QC message");
    high_qc.signatures = keyed
        .iter()
        .take(3)
        .map(|(account, key, _)| (*account, key.sign(&high_qc_message).unwrap().to_bytes()))
        .collect();
    let timeout = |view| {
        let votes = keyed
            .iter()
            .take(3)
            .map(|(account, key, _)| {
                let mut vote = AftTimeoutVoteV1::unsigned(
                    scope,
                    NATIVE_HEIGHT,
                    view,
                    *account,
                    high_qc.clone(),
                    high_qc.clone(),
                );
                let message = vote.signing_bytes().expect("timeout signing bytes");
                vote.signature = key.sign(&message).unwrap().to_bytes();
                vote
            })
            .collect();
        AftTimeoutCertificateV1::new(scope, NATIVE_HEIGHT, view, votes).expect("timeout shapes")
    };
    let start = FallbackStartCertificateV1::new(
        scope,
        NATIVE_HEIGHT,
        AftFallbackTriggerCertificateV1 {
            height: NATIVE_HEIGHT,
            consecutive_timeout_certificates: vec![timeout(1), timeout(2), timeout(3)],
        },
    )
    .expect("fallback start shapes");
    let instance =
        AftAsyncInstanceV1::from_fallback_start(&start, AftAsyncGeometryV1::exact(4).unwrap())
            .expect("instance shapes");
    let proposal = AftAsyncBatchProposalV1::new(&instance, Vec::new()).unwrap();
    let payload = to_bytes_canonical(&proposal).unwrap();
    let mut witnesses = Vec::new();
    let mut references = Vec::new();
    for proposer in 0..3_u16 {
        let descriptor = AftAsyncProposalDescriptorV1 {
            instance_hash: instance.instance_hash().unwrap(),
            proposer,
            proposal_hash: aft_async_proposal_payload_hash(&payload).unwrap(),
            payload_len: payload.len() as u64,
            parent_root: instance.locked_root,
        };
        let votes = (0..3_u16)
            .map(|member_index| {
                let voter = keyed[member_index as usize].0;
                let message = AftAsyncProposalAvailabilityVoteV1::signing_bytes(
                    &descriptor,
                    member_index,
                    voter,
                )
                .unwrap();
                AftAsyncProposalAvailabilityVoteV1 {
                    proposal_binding_hash: descriptor.binding_hash().unwrap(),
                    member_index,
                    voter,
                    signature_suite: SignatureSuite::ML_DSA_44,
                    signature: keyed[member_index as usize]
                        .1
                        .sign(&message)
                        .unwrap()
                        .to_bytes(),
                }
            })
            .collect();
        let availability = AftAsyncProposalAvailabilityCertificateV1 {
            protocol_version: AFT_ASYNC_PROTOCOL_VERSION_V1,
            schema_version: AFT_ASYNC_SCHEMA_VERSION_V1,
            descriptor,
            votes,
        };
        references.push(availability.proposal_ref(&instance).unwrap());
        witnesses.push(AftAsyncSelectedProposalWitnessV1 {
            proposal: proposal.clone(),
            availability_certificate: availability,
        });
    }
    let transcript = AftAsyncTranscriptSummaryV1::new(&instance, 0, references.clone()).unwrap();
    let ordering_decision = AftAsyncOrderingDecisionV1::new(
        instance.clone(),
        references,
        transcript.transcript_root(&instance).unwrap(),
    )
    .unwrap();
    let ordering_votes = (0..3_u16)
        .map(|member_index| {
            let voter = keyed[member_index as usize].0;
            let message =
                AftAsyncDecisionVoteV1::signing_bytes(&ordering_decision, member_index, voter)
                    .unwrap();
            AftAsyncDecisionVoteV1 {
                decision_hash: ordering_decision.decision_hash().unwrap(),
                member_index,
                voter,
                signature_suite: SignatureSuite::ML_DSA_44,
                signature: keyed[member_index as usize]
                    .1
                    .sign(&message)
                    .unwrap()
                    .to_bytes(),
            }
        })
        .collect();
    let ordering = AftAsyncOrderingCertificateV1 {
        protocol_version: AFT_ASYNC_PROTOCOL_VERSION_V1,
        schema_version: AFT_ASYNC_SCHEMA_VERSION_V1,
        decision: ordering_decision,
        transcript,
        votes: ordering_votes,
    };
    let batch_witness = AftAsyncSelectedBatchWitnessV1 {
        selected: witnesses,
    };
    let mut header = native_header(&members, NATIVE_HEIGHT, 4);
    header.parent_hash = high_qc.block_hash;
    header.parent_qc = aft_async_canonical_qc_reference(&high_qc);
    header.transactions_root = canonical_transactions_root(&[]).unwrap();
    header.producer_key_suite = SignatureSuite::ML_DSA_44;
    header.producer_account_id = keyed[0].0;
    header.producer_pubkey_hash = keyed[0].0 .0;
    header.producer_pubkey = keyed[0].2.clone();
    header.signature.clear();
    let block = Block {
        header,
        transactions: Vec::new(),
    };
    let block_hash: [u8; 32] = block.header.hash().unwrap().as_slice().try_into().unwrap();
    let executed_decision =
        AftAsyncExecutedBlockDecisionV1::new(ordering.clone(), batch_witness.clone(), block_hash)
            .unwrap();
    let executed_votes = (0..3_u16)
        .map(|member_index| {
            let voter = keyed[member_index as usize].0;
            let message =
                AftAsyncExecutedBlockVoteV1::signing_bytes(&executed_decision, member_index, voter)
                    .unwrap();
            AftAsyncExecutedBlockVoteV1 {
                decision_hash: executed_decision.decision_hash().unwrap(),
                member_index,
                voter,
                signature_suite: SignatureSuite::ML_DSA_44,
                signature: keyed[member_index as usize]
                    .1
                    .sign(&message)
                    .unwrap()
                    .to_bytes(),
            }
        })
        .collect();
    let subject = if admit_parent { &parent_block } else { &block };
    let finalized = NativeAftHashAsyncFinalizedBlock {
        block_header_bytes: to_bytes_canonical(&subject.header).unwrap(),
        terminal_block_header_bytes: to_bytes_canonical(&block.header).unwrap(),
        certificate: AftAsyncExecutedBlockCertificateV1 {
            protocol_version: AFT_ASYNC_PROTOCOL_VERSION_V1,
            schema_version: AFT_ASYNC_SCHEMA_VERSION_V1,
            decision: executed_decision,
            ordering,
            votes: executed_votes,
        },
        witness: batch_witness,
        validator_set: set,
        members,
        membership_ref: "node-membership://acme/hash-async/1".into(),
        membership_epoch: 1,
    };
    let input = RuntimeBundleV3Input {
        bundle_id: "proof://acme/runtime/hash-async/7",
        checkpoint_id: "receipt-checkpoint://acme/runtime/hash-async/7",
        certificate_id: "finality-certificate://acme/runtime/hash-async/7",
        availability_manifest_id: "availability-manifest://acme/runtime/hash-async/7",
        block_payload_ref: "payload://acme/runtime/hash-async/block/7",
        domain_id: "domain://acme/runtime/hash-async",
        authority_epoch: 9,
        authority_revocation_epoch: 4,
        profile: RuntimeFinalityProfile::BftConsensusAftV1,
        profile_epoch: 3,
        writer_identity: "writer://acme/validator/1",
        fence_token: 17,
        operation_sequence_first: 41,
        receipt_sequence_first: 81,
        previous_checkpoint_ref: None,
        previous_checkpoint_hash: None,
        authority_policy_root: RUNTIME_TEST_HASH,
        governance_policy_root: RUNTIME_TEST_HASH,
        availability_policy_root: RUNTIME_TEST_HASH,
        retention_policy_root: RUNTIME_TEST_HASH,
        location_ref: "agentgres://acme/runtime/hash-async/block/7",
        failure_domain_ref: "failure-domain://acme/local-device",
        verifier_contract_hash: RUNTIME_TEST_HASH,
        issuer_key_id: "key://acme/finality/9",
        block: subject,
        receipts: &[],
        native_aft: None,
        hash_async: Some(&finalized),
    };
    let member_keys = keyed
        .iter()
        .map(|(account, key, _)| (*account, key.clone()))
        .collect();
    let bundle = if pq_issuer {
        let issuer = scheme.generate_keypair().expect("PQ runtime issuer");
        emit_runtime_bundle_v3_pq(input, &issuer)
            .expect("PQ hash-async runtime bundle emits and self-verifies")
    } else {
        emit_runtime_bundle_v3(input, &native_issuer())
            .expect("hash-async runtime bundle emits and self-verifies")
    };
    (bundle, member_keys)
}

#[test]
fn runtime_v3_hash_async_supports_pq_checkpoint_issuer_without_downgrade() {
    let bundle = runtime_v3_hash_async_pq_issuer_bundle();
    assert_eq!(
        bundle
            .pointer("/checkpoint/finality_certificate/signature_suite")
            .and_then(Value::as_str),
        Some("ml-dsa-44")
    );
    let claim = verify_runtime_bundle_v3(&bundle).expect("PQ issuer verifies offline");
    assert!(claim.assurance.crypto.consensus_pq);
    assert!(!claim.assurance.crypto.private_threshold_setup);
}

fn rehash_runtime_outer(bundle: &mut Value) {
    let outer = hash_value(&without(bundle, &["bundle_hash"]).expect("bundle preimage"))
        .expect("bundle hash");
    set_text(bundle, "bundle_hash", outer).expect("sets bundle hash");
}

/// Re-sign a mutated runtime certificate with the trusted issuer. This makes
/// native-evidence tests prove the peer rule itself rather than stopping at the
/// outer issuer signature.
fn reissue_runtime_certificate(bundle: &mut Value) {
    let issuer = native_issuer();
    let certificate = bundle
        .pointer_mut("/checkpoint/finality_certificate")
        .expect("runtime certificate");
    let body_hash = hash_value(
        &without(certificate, &["body_hash", "signature"]).expect("certificate preimage"),
    )
    .expect("certificate hash");
    set_text(certificate, "body_hash", body_hash.clone()).expect("sets certificate hash");
    let signature = issuer
        .sign(format!("{RUNTIME_CERTIFICATE_V2}\0{body_hash}").as_bytes())
        .expect("issuer re-signs runtime certificate");
    set_text(certificate, "signature", hex::encode(signature.to_bytes()))
        .expect("sets certificate signature");
    rehash_runtime_outer(bundle);
}

#[test]
fn runtime_v3_binds_both_real_profiles_without_inventing_receipt_commitment() {
    let aft = verify_runtime_bundle_v3(&runtime_v3_bundle(
        RuntimeFinalityProfile::BftConsensusAftV1,
    ))
    .expect("AFT runtime bundle verifies");
    assert_eq!(aft.profile, "bft_consensus");
    assert_eq!(aft.certificate_variant, "bft_consensus_aft_v1");
    assert_eq!(aft.operation_count, 3);
    assert_eq!(aft.receipt_count, 3);
    assert!(aft.native_quorum_verified);
    assert!(aft.effect_committed_in_block);
    assert!(!aft.receipts_committed_in_block);
    assert_eq!(aft.profile_epoch, 3);
    assert_eq!(aft.fence_token, 17);

    let single = verify_runtime_bundle_v3(&runtime_v3_bundle(
        RuntimeFinalityProfile::SingleAuthorityV1,
    ))
    .expect("single-authority runtime bundle verifies");
    assert_eq!(single.profile, "single_authority");
    assert_eq!(single.certificate_variant, "single_authority_v1");
    assert!(!single.native_quorum_verified);
    assert!(single.effect_committed_in_block);
    assert!(!single.receipts_committed_in_block);
}

#[test]
fn runtime_v3_empty_block_advances_with_a_block_transition_receipt() {
    let (fixture, block_bytes, _) = native_effect_fixture(Vec::new(), 42);
    let block: Block<ChainTransaction> =
        from_bytes_canonical(&block_bytes).expect("empty runtime block decodes");
    let bundle = emit_runtime_bundle_v3(
        RuntimeBundleV3Input {
            bundle_id: "proof://acme/runtime/empty/8",
            checkpoint_id: "receipt-checkpoint://acme/runtime/empty/8",
            certificate_id: "finality-certificate://acme/runtime/empty/8",
            availability_manifest_id: "availability-manifest://acme/runtime/empty/8",
            block_payload_ref: "payload://acme/runtime/block/empty/8",
            domain_id: "domain://acme/runtime",
            authority_epoch: 9,
            authority_revocation_epoch: 4,
            profile: RuntimeFinalityProfile::BftConsensusAftV1,
            profile_epoch: 3,
            writer_identity: "writer://acme/validator/1",
            fence_token: 17,
            operation_sequence_first: 44,
            receipt_sequence_first: 84,
            previous_checkpoint_ref: None,
            previous_checkpoint_hash: None,
            authority_policy_root: RUNTIME_TEST_HASH,
            governance_policy_root: RUNTIME_TEST_HASH,
            availability_policy_root: RUNTIME_TEST_HASH,
            retention_policy_root: RUNTIME_TEST_HASH,
            location_ref: "agentgres://acme/runtime/block/empty/8",
            failure_domain_ref: "failure-domain://acme/local-device",
            verifier_contract_hash: RUNTIME_TEST_HASH,
            issuer_key_id: "key://acme/finality/9",
            block: &block,
            receipts: &[],
            native_aft: Some(&fixture.finalized),
            hash_async: None,
        },
        &native_issuer(),
    )
    .expect("empty block emits through the explicit v3 successor");
    let claim = verify_runtime_bundle_v3(&bundle).expect("empty block verifies offline");
    assert_eq!(claim.operation_count, 1);
    assert_eq!(claim.receipt_count, 1);
    assert!(claim.native_quorum_verified);
}

#[test]
fn runtime_v3_verifier_never_reinterprets_predecessor_versions() {
    for version in [
        "schema://ioi/foundations/receipt-proof-bundle/v1",
        BUNDLE_V2,
        "ioi.foundations.receipt-proof-bundle.v4",
    ] {
        assert_eq!(
            verify_runtime_bundle_v3(&json!({"schema_version": version})),
            Err(VerificationError::UnsupportedVersion(version.to_owned()))
        );
    }
}

#[test]
fn runtime_v3_signed_boundary_substitutions_fail_closed() {
    let original = runtime_v3_bundle(RuntimeFinalityProfile::BftConsensusAftV1);
    let substitutions = [
        ("/checkpoint/profile", json!("single_authority")),
        ("/checkpoint/writer_fence/profile_epoch", json!(4)),
        (
            "/checkpoint/writer_fence/writer_identity",
            json!("writer://stale"),
        ),
        ("/checkpoint/writer_fence/fence_token", json!(18)),
        ("/checkpoint/authority_epoch", json!(10)),
        ("/checkpoint/authority_revocation_epoch", json!(5)),
        (
            "/checkpoint/previous_canonical_head",
            json!(RUNTIME_TEST_HASH),
        ),
        ("/operations/0/sequence", json!(42)),
        ("/operations/1/body/transaction_base64", json!("AA==")),
        ("/receipts/1/body/gas_used", json!(1)),
        (
            "/checkpoint/resulting_state_commitment/root_base64",
            json!("AA=="),
        ),
        ("/availability_payloads/0/payload_base64", json!("AA==")),
        (
            "/checkpoint/verifier_contract_hash",
            json!(RUNTIME_TEST_HASH.replace('a', "b")),
        ),
        (
            "/checkpoint/availability_policy_root",
            json!(RUNTIME_TEST_HASH.replace('a', "d")),
        ),
        (
            "/checkpoint/availability_manifest/retention_policy_root",
            json!(RUNTIME_TEST_HASH.replace('a', "c")),
        ),
    ];
    for (pointer, replacement) in substitutions {
        let mut bundle = original.clone();
        *bundle.pointer_mut(pointer).expect("substitution pointer") = replacement;
        rehash_runtime_outer(&mut bundle);
        assert!(
            verify_runtime_bundle_v3(&bundle).is_err(),
            "runtime substitution unexpectedly verified: {pointer}"
        );
    }
}

#[test]
fn runtime_v3_peer_evidence_refuses_forgery_even_after_issuer_reissue() {
    let mut forged = runtime_v3_bundle(RuntimeFinalityProfile::BftConsensusAftV1);
    forged["checkpoint"]["finality_certificate"]["native_aft_evidence"]["votes"][0]["signature"] =
        Value::String("00".repeat(64));
    reissue_runtime_certificate(&mut forged);
    assert!(matches!(
        verify_runtime_bundle_v3(&forged),
        Err(VerificationError::ConsensusEvidence(_) | VerificationError::Crypto(_))
    ));

    let mut relabelled = runtime_v3_bundle(RuntimeFinalityProfile::BftConsensusAftV1);
    relabelled["checkpoint"]["finality_certificate"]["native_aft_evidence"]["fault_model"] =
        Value::String("crash".into());
    reissue_runtime_certificate(&mut relabelled);
    assert!(matches!(
        verify_runtime_bundle_v3(&relabelled),
        Err(VerificationError::ConsensusEvidence(_))
    ));
}

#[test]
fn runtime_v3_reverifies_ml_dsa_quorum_without_downgrade() {
    let bundle = runtime_v3_pq_bundle();
    let claim = verify_runtime_bundle_v3(&bundle).expect("PQ quorum verifies offline");
    assert!(claim.native_quorum_verified);
    let members = bundle
        .pointer("/checkpoint/finality_certificate/native_aft_evidence/members")
        .and_then(Value::as_array)
        .expect("PQ evidence members");
    assert!(members.iter().all(|member| {
        member.get("signature_suite").and_then(Value::as_str) == Some("ml-dsa-44")
    }));

    let mut relabelled = bundle;
    relabelled["checkpoint"]["finality_certificate"]["native_aft_evidence"]["members"][0]
        ["signature_suite"] = Value::String("ed25519".into());
    reissue_runtime_certificate(&mut relabelled);
    assert!(verify_runtime_bundle_v3(&relabelled).is_err());
}

#[test]
fn runtime_v3_reverifies_hash_async_chain_without_synthetic_qc() {
    let bundle = runtime_v3_hash_async_bundle();
    let claim = verify_runtime_bundle_v3(&bundle).expect("hash-async chain verifies offline");
    assert!(claim.native_quorum_verified);
    assert!(claim.effect_committed_in_block);
    assert!(claim.assurance.crypto.consensus_pq);
    assert!(!claim.assurance.crypto.channel_pq);
    assert!(!claim.assurance.crypto.end_to_end_pq);
    assert_eq!(
        claim.assurance.liveness.termination,
        TerminationV1::RandomizedAsynchronous
    );
    let evidence = bundle
        .pointer("/checkpoint/finality_certificate/hash_async_evidence")
        .expect("distinct hash-async evidence exists");
    assert_eq!(
        evidence
            .get("consensus_protocol_ref")
            .and_then(Value::as_str),
        Some("protocol://ioi/aft/hash-async/v1")
    );
    assert_eq!(
        evidence
            .get("private_threshold_setup")
            .and_then(Value::as_bool),
        Some(false)
    );
    assert_eq!(
        evidence
            .get("membership_enrollment_required")
            .and_then(Value::as_bool),
        Some(true)
    );
    assert_eq!(
        evidence
            .get("private_authenticated_channels_required")
            .and_then(Value::as_bool),
        Some(true)
    );
    assert_eq!(
        evidence
            .get("pq_authenticated_channels_required")
            .and_then(Value::as_bool),
        Some(true)
    );
    assert!(bundle
        .pointer("/checkpoint/finality_certificate/native_aft_evidence")
        .is_none());
}

#[test]
fn runtime_v3_reissued_wrapper_cannot_launder_assurance_vector() {
    let mut bundle = runtime_v3_hash_async_bundle();
    bundle["checkpoint"]["finality_certificate"]["assurance"]["achieved"]["crypto"]["channel_pq"] =
        Value::Bool(true);
    reissue_runtime_certificate(&mut bundle);
    assert!(matches!(
        verify_runtime_bundle_v3(&bundle),
        Err(VerificationError::ConsensusEvidence(_))
    ));
}

#[test]
fn portable_verifier_reloads_hash_async_receipt_from_disk_and_refuses_mutation() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("hash-async-runtime-v3.json");
    let bundle = runtime_v3_hash_async_bundle();
    fs::write(&path, serde_json::to_vec_pretty(&bundle).unwrap()).unwrap();

    let reloaded: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    let claim = verify_portable_bundle(&reloaded).expect("reloaded receipt verifies offline");
    assert!(matches!(claim, VerifiedPortableClaim::RuntimeV3(_)));

    let mut mutated = reloaded;
    let encoded = mutated
        .pointer("/checkpoint/finality_certificate/hash_async_evidence/certificate_base64")
        .and_then(Value::as_str)
        .unwrap();
    let mut certificate: AftAsyncExecutedBlockCertificateV1 =
        from_bytes_canonical(&BASE64.decode(encoded).unwrap()).unwrap();
    certificate
        .decision
        .instance
        .fallback_start
        .trigger_certificate
        .consecutive_timeout_certificates[0]
        .votes[0]
        .signature[0] ^= 1;
    mutated["checkpoint"]["finality_certificate"]["hash_async_evidence"]["certificate_base64"] =
        Value::String(BASE64.encode(to_bytes_canonical(&certificate).unwrap()));
    reissue_runtime_certificate(&mut mutated);
    fs::write(&path, serde_json::to_vec_pretty(&mutated).unwrap()).unwrap();
    let reloaded_mutation: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    assert!(matches!(
        verify_portable_bundle(&reloaded_mutation),
        Err(VerificationError::ConsensusEvidence(_) | VerificationError::Crypto(_))
    ));
}

#[test]
fn runtime_v3_hash_async_direct_parent_receipt_retains_terminal_proof() {
    let bundle = runtime_v3_hash_async_parent_bundle();
    let claim = verify_runtime_bundle_v3(&bundle)
        .expect("direct high-QC parent verifies through terminal hash-async evidence");
    assert!(claim.native_quorum_verified);
    assert!(claim.effect_committed_in_block);
    assert!(bundle
        .pointer("/checkpoint/finality_certificate/native_aft_evidence")
        .is_none());
    let terminal = bundle
        .pointer(
            "/checkpoint/finality_certificate/hash_async_evidence/terminal_block_header_base64",
        )
        .and_then(Value::as_str)
        .expect("parent receipt retains its terminal virtual header");
    assert!(!BASE64.decode(terminal).unwrap().is_empty());
}

#[test]
fn runtime_v3_hash_async_signature_mutation_fails_after_issuer_reissue() {
    let mut bundle = runtime_v3_hash_async_bundle();
    let encoded = bundle
        .pointer("/checkpoint/finality_certificate/hash_async_evidence/certificate_base64")
        .and_then(Value::as_str)
        .unwrap();
    let bytes = BASE64.decode(encoded).unwrap();
    let mut certificate: AftAsyncExecutedBlockCertificateV1 = from_bytes_canonical(&bytes).unwrap();
    certificate.votes[0].signature[0] ^= 1;
    bundle["checkpoint"]["finality_certificate"]["hash_async_evidence"]["certificate_base64"] =
        Value::String(BASE64.encode(to_bytes_canonical(&certificate).unwrap()));
    reissue_runtime_certificate(&mut bundle);
    assert!(matches!(
        verify_runtime_bundle_v3(&bundle),
        Err(VerificationError::ConsensusEvidence(_) | VerificationError::Crypto(_))
    ));

    let mut bundle = runtime_v3_hash_async_bundle();
    let encoded = bundle
        .pointer("/checkpoint/finality_certificate/hash_async_evidence/certificate_base64")
        .and_then(Value::as_str)
        .unwrap();
    let bytes = BASE64.decode(encoded).unwrap();
    let mut certificate: AftAsyncExecutedBlockCertificateV1 = from_bytes_canonical(&bytes).unwrap();
    certificate
        .decision
        .instance
        .fallback_start
        .trigger_certificate
        .consecutive_timeout_certificates[0]
        .votes[0]
        .signature[0] ^= 1;
    bundle["checkpoint"]["finality_certificate"]["hash_async_evidence"]["certificate_base64"] =
        Value::String(BASE64.encode(to_bytes_canonical(&certificate).unwrap()));
    reissue_runtime_certificate(&mut bundle);
    assert!(matches!(
        verify_runtime_bundle_v3(&bundle),
        Err(VerificationError::ConsensusEvidence(_) | VerificationError::Crypto(_))
    ));
}

#[test]
fn hash_async_execution_refuses_omitted_reordered_or_extra_transactions() {
    let first = native_effect_transaction(1);
    let second = native_effect_transaction(2);
    let selected = vec![first.clone(), second.clone()];

    assert!(super::runtime_v3::hash_async_executed_batch_matches(
        &selected, &selected
    ));
    assert!(!super::runtime_v3::hash_async_executed_batch_matches(
        &selected,
        std::slice::from_ref(&first)
    ));
    assert!(!super::runtime_v3::hash_async_executed_batch_matches(
        &selected,
        &[second.clone(), first.clone()]
    ));
    assert!(!super::runtime_v3::hash_async_executed_batch_matches(
        &selected,
        &[first, second.clone(), second]
    ));
}
