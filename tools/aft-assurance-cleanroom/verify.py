#!/usr/bin/env python3
"""Independent stdlib verifier for AFT canonical/economic golden vectors.

For complete receipts this first requires a separately supplied canonical
trust policy, then reproduces the outer JCS subset, receipt hash,
manifest/consequence bindings, collateral distinctness/floor, transform names,
and both embedded and relying-party policy decisions. ML-DSA verification is
delegated only to the separately versioned RustCrypto oracle in
tools/aft-pq-interop, never to IOI runtime code.
"""

import argparse
import base64
import copy
import hashlib
import json
import subprocess
import sys
from pathlib import Path

SCHEMA = "ioi.aft.portable-assurance-receipt.v1"
PROFILE = "verifier://ioi/aft/portable-assurance/v1"
TRUST_SCHEMA = "ioi.aft.portable-assurance-trust.v1"
SIG_DOMAIN = b"ioi::aft::portable-assurance-receipt::v1\0"
RESOURCE_PROFILE_DOMAIN = b"ioi::aft::external-resource-profile::v1\0"
EFFECT_MANIFEST_DOMAIN = b"ioi::aft::effect-manifest::v1\0"
CONFLICT_DOMAIN = b"ioi::aft::conflict-domain-id::v1\0"
EXTERNALIZATION_SIG_DOMAIN = b"ioi::aft::portable-externalization-evidence::v1\0"
CONFIGURATION_VOTE_DOMAIN = b"ioi::aft::configuration-key-root-vote::v1\0"
TERMINAL_ROOT_DOMAIN = b"ioi::aft::portable-terminal-seal-root::v1\0"
SEAL_KEY_DOMAIN = b"ioi.aft.seal-key-commitment.v1\0"
SEAL_MANIFEST_DOMAIN = b"ioi.aft.seal-key-manifest.v1\0"
SEAL_SHARE_DOMAIN = b"ioi.aft.seal-share.v2\0"
BOND_SNAPSHOT_DOMAIN = b"ioi::aft::bond-snapshot::v1\0"
COLLATERAL_SET_DOMAIN = b"ioi::aft::collateral-set::v1\0"
ACCOUNTABILITY_DOMAIN = b"ioi::aft::accountability-evidence::v1\0"
ECONOMIC_DOMAIN = b"ioi::aft::economic-assurance::v1\0"
ACCOUNT_ID_DOMAIN = b"IOI-ACCOUNT-ID::V1"
CHANNEL_PROFILE = b"aft-pq-channel-v1"
CLIENT_HELLO_DOMAIN = b"ioi::aft::pq-channel::client-hello::v1\0"
SERVER_HELLO_DOMAIN = b"ioi::aft::pq-channel::server-hello::v1\0"
CLIENT_FINISH_DOMAIN = b"ioi::aft::pq-channel::client-finish::v1\0"
CHANNEL_COMPLETION_DOMAIN = b"ioi::aft::pq-channel::completion-evidence::v1\0"
GUARANTEE_VECTOR_DOMAIN = b"ioi::aft::guarantee-vector::v1\0"


def canonical(value):
    # Receipt schemas forbid floats and use only strings, safe integers,
    # booleans, arrays and objects; for that closed subset this equals JCS.
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":")).encode()


def sha(value):
    return "sha256:" + hashlib.sha256(canonical(value)).hexdigest()


def digest(value):
    return hashlib.sha256(canonical(value)).digest()


def domain_digest(domain, value):
    return hashlib.sha256(domain + canonical(value)).digest()


def exact_keys(value, required, label, optional=()):
    assert isinstance(value, dict), f"{label} must be an object"
    required, optional = set(required), set(optional)
    actual = set(value)
    unknown = actual - required - optional
    missing = required - actual
    assert not unknown, f"{label} contains unknown fields: {sorted(unknown)}"
    assert not missing, f"{label} is missing fields: {sorted(missing)}"


def close_requirements(value, label):
    exact_keys(value, {
        "minimum_finality_rank", "configuration_hash", "conflict_domain_hash",
        "require_consensus_pq", "require_channel_pq", "require_externalization_pq",
        "require_end_to_end_pq", "require_no_private_threshold_setup",
        "minimum_accountability", "require_publication_retrievable",
        "minimum_externalization", "require_at_most_once",
    }, label, {"minimum_slashable_collateral"})
    floor = value.get("minimum_slashable_collateral")
    if floor is not None:
        exact_keys(floor, {"asset_id_hash", "minimum_amount_base_units"}, label + ".minimum_slashable_collateral")


def close_guarantee_vector(value, label):
    exact_keys(value, {
        "schema_version", "safety", "liveness", "crypto", "accountability",
        "availability", "externalization", "slashable_collateral",
        "measured_latency", "assumptions", "theorem_ids", "certificate_profiles",
        "constituent_hashes", "transformation_hashes",
    }, label)
    exact_keys(value["safety"], {
        "model", "finality_rank", "committee_n", "fault_bound_f", "quorum_q",
        "configuration_hash", "conflict_domain_hash",
    }, label + ".safety")
    exact_keys(value["liveness"], {
        "termination", "network", "adversary", "committee_n", "fault_bound_f",
        "private_authenticated_channels",
    }, label + ".liveness")
    exact_keys(value["crypto"], {
        "consensus_pq", "channel_pq", "externalization_pq", "end_to_end_pq",
        "private_threshold_setup", "primitive_suites",
    }, label + ".crypto")
    exact_keys(value["availability"], {
        "publication_retrievable", "custody_threshold", "retention_horizon",
    }, label + ".availability")
    exact_keys(value["externalization"], {
        "mode", "at_most_once", "adapter_profile_hash",
    }, label + ".externalization")
    collateral = value["slashable_collateral"]
    if collateral is not None:
        exact_keys(collateral, {
            "asset_id_hash", "amount_base_units", "collateral_set_hash",
            "bond_snapshot_root", "locked_until", "evidence_rule_hash",
            "slashing_contract_hash", "valuation_assumptions_hash",
        }, label + ".slashable_collateral")
    latency = value["measured_latency"]
    if latency is not None:
        exact_keys(latency, {"profile_hash", "percentile_bps", "milliseconds"}, label + ".measured_latency")


def close_runtime_bundle(bundle):
    exact_keys(bundle, {
        "schema_version", "bundle_domain", "bundle_id", "bundle_hash", "checkpoint",
        "operations", "receipts", "availability_payloads", "trusted_issuer",
        "requested_axes", "compatibility_behavior",
    }, "finality_bundle")
    checkpoint = bundle["checkpoint"]
    exact_keys(checkpoint, {
        "schema_version", "checkpoint_domain", "checkpoint_id", "body_hash", "domain_id",
        "authority_epoch", "authority_revocation_epoch", "operation_range", "receipt_range",
        "previous_checkpoint_ref", "previous_checkpoint_hash", "previous_canonical_head",
        "resulting_canonical_head", "previous_state_commitment", "resulting_state_commitment",
        "operation_root", "receipt_root", "profile_contract_version", "profile", "writer_fence",
        "authority_policy_root", "governance_policy_root", "availability_policy_root",
        "availability_manifest", "availability_manifest_hash", "verifier_contract_ref",
        "verifier_contract_hash", "durability_class", "finality_certificate",
    }, "finality_bundle.checkpoint")
    for name in ("operation_range", "receipt_range"):
        exact_keys(checkpoint[name], {"first", "last"}, "checkpoint." + name)
    for name in ("previous_state_commitment", "resulting_state_commitment"):
        exact_keys(checkpoint[name], {"algorithm", "height", "root_base64", "root_hash"}, "checkpoint." + name)
    exact_keys(checkpoint["writer_fence"], {"profile_epoch", "writer_identity", "fence_token"}, "checkpoint.writer_fence")
    manifest = checkpoint["availability_manifest"]
    exact_keys(manifest, {"schema_version", "manifest_id", "manifest_hash", "retention_class",
                          "retention_policy_root", "payloads", "failure_behavior"}, "availability_manifest")
    for row in manifest["payloads"]:
        exact_keys(row, {"payload_ref", "payload_hash", "byte_length", "location_ref",
                         "failure_domain_ref"}, "availability_manifest.payload")
    certificate = checkpoint["finality_certificate"]
    exact_keys(certificate, {
        "schema_version", "certificate_domain", "certificate_variant", "certificate_id",
        "domain_id", "authority_epoch", "authority_revocation_epoch", "checkpoint_hash",
        "operation_range", "receipt_range", "profile_contract_version", "profile",
        "profile_epoch", "writer_identity", "fence_token", "claimed_axes", "assurance",
        "verifier_contract_ref", "verifier_contract_hash", "issuer_key_id",
        "issuer_public_key", "body_hash", "signature_suite", "signature",
    }, "finality_certificate", {"native_aft_evidence", "hash_async_evidence"})
    for name in ("operation_range", "receipt_range"):
        exact_keys(certificate[name], {"first", "last"}, "finality_certificate." + name)
    assurance = certificate["assurance"]
    exact_keys(assurance, {"schema_version", "requirements", "achieved",
                           "achieved_commitment", "transformations"}, "finality_certificate.assurance")
    close_requirements(assurance["requirements"], "finality_certificate.assurance.requirements")
    close_guarantee_vector(assurance["achieved"], "finality_certificate.assurance.achieved")
    for transform in assurance["transformations"]:
        exact_keys(transform, {"schema_version", "coordinate", "rule", "input_vector_hashes",
                               "new_evidence_hash", "theorem_id", "verifier_profile_hash",
                               "claimed_output_hash"}, "finality_certificate.assurance.transform")
    hash_evidence = certificate.get("hash_async_evidence")
    if hash_evidence is not None:
        exact_keys(hash_evidence, {
            "schema_version", "consensus_protocol_ref", "membership_ref", "membership_epoch",
            "fault_model", "synchrony_model", "private_threshold_setup",
            "membership_enrollment_required", "private_authenticated_channels_required",
            "pq_authenticated_channels_required", "post_quantum", "terminal_block_header_base64",
            "certificate_base64", "witness_base64", "validator_set_base64", "members",
        }, "finality_certificate.hash_async_evidence")
        for member in hash_evidence["members"]:
            exact_keys(member, {"member_ref", "signature_suite", "public_key"}, "hash_async_evidence.member")
    native = certificate.get("native_aft_evidence")
    if native is not None:
        exact_keys(native, {
            "schema_version", "consensus_protocol_ref", "membership_ref", "membership_epoch",
            "fault_model", "synchrony_model", "total_voting_members",
            "byzantine_fault_tolerance", "quorum_threshold", "block_height", "block_view",
            "block_hash", "vote_message_domain", "effect_commitment", "membership_hash",
            "members", "votes",
        }, "finality_certificate.native_aft_evidence")
        for member in native["members"]:
            exact_keys(member, {"member_ref", "signature_suite", "public_key"}, "native_aft_evidence.member")
        for vote in native["votes"]:
            exact_keys(vote, {"member_ref", "account_id", "signature"}, "native_aft_evidence.vote")
    for material in bundle["operations"] + bundle["receipts"]:
        # `body` is deliberately a Value in the Rust schema; its hash is still checked.
        exact_keys(material, {"sequence", "body", "body_hash"}, "finality_bundle.material")
    for payload in bundle["availability_payloads"]:
        exact_keys(payload, {"payload_ref", "payload_base64"}, "finality_bundle.availability_payload")
    exact_keys(bundle["trusted_issuer"], {"issuer_key_id", "issuer_public_key", "domain_id",
                                         "authority_epoch", "revocation_epoch"}, "finality_bundle.trusted_issuer")


def close_portable_schema(receipt, trust):
    exact_keys(receipt, {
        "schema_version", "verifier_profile", "finality_bundle", "channel_coverage",
        "terminal_seal", "effect_manifest", "policy", "configuration_snapshot",
        "consequence", "economic_proof", "requested_anchors", "claimed_achieved",
        "transformation_trace", "receipt_hash", "signature",
    }, "receipt")
    exact_keys(trust, {
        "schema_version", "network_id", "configuration_hash", "epoch", "terminal_key_root",
        "allowed_receipt_public_keys_base64", "required_anchors", "required_guarantees",
    }, "trust")
    close_requirements(receipt["policy"], "receipt.policy")
    close_requirements(trust["required_guarantees"], "trust.required_guarantees")
    close_guarantee_vector(receipt["claimed_achieved"], "receipt.claimed_achieved")
    close_runtime_bundle(receipt["finality_bundle"])

    coverage = receipt["channel_coverage"]
    exact_keys(coverage, {"schema_version", "network_id", "configuration_hash", "epoch",
                          "protected_finality_hash", "sessions"}, "receipt.channel_coverage")
    for session in coverage["sessions"]:
        exact_keys(session, {"protocol_version", "schema_version", "profile", "client_hello",
                             "server_hello", "client_finish", "protected_payload_hash",
                             "initiator_attestation_signature", "responder_attestation_signature"},
                   "channel_coverage.session")
        hello = session["client_hello"]
        exact_keys(hello, {"protocol_version", "schema_version", "scope", "nonce",
                           "kem_public_key", "identity_suite", "identity_public_key", "signature"},
                   "channel.client_hello")
        exact_keys(hello["scope"], {"network_id", "configuration_hash", "epoch", "initiator",
                                    "responder", "initiator_transport_binding",
                                    "responder_transport_binding"}, "channel.scope")
        exact_keys(session["server_hello"], {"protocol_version", "schema_version", "client_hello_hash",
                                             "nonce", "kem_ciphertext", "identity_suite",
                                             "identity_public_key", "signature"}, "channel.server_hello")
        exact_keys(session["client_finish"], {"protocol_version", "schema_version", "transcript_hash",
                                              "key_confirmation", "signature"}, "channel.client_finish")

    terminal = receipt["terminal_seal"]
    exact_keys(terminal, {"schema_version", "key_manifest", "shares"}, "receipt.terminal_seal")
    exact_keys(terminal["key_manifest"], {"schema_version", "entries"}, "terminal_seal.key_manifest")
    for entry in terminal["key_manifest"]["entries"]:
        exact_keys(entry, {"initial_key", "initial_key_commitment"}, "terminal_seal.manifest_entry")
        close_seal_key(entry["initial_key"], "terminal_seal.initial_key")
    for share in terminal["shares"]:
        exact_keys(share, {"protocol_version", "schema_version", "current_key", "seal_slot",
                           "seal_root", "next_key_commitment", "signature"}, "terminal_seal.share")
        close_seal_key(share["current_key"], "terminal_seal.current_key")

    manifest = receipt["effect_manifest"]
    exact_keys(manifest, {"schema_version", "effect_id", "resource_id", "conflict_domain_id",
                          "read_set", "write_set", "idempotency_key", "request_root",
                          "predecessor_root", "intent_root", "expected_outcome_root",
                          "resource_profile", "required_guarantees", "fence", "reconciliation",
                          "irreversible"}, "receipt.effect_manifest")
    for row in manifest["read_set"] + manifest["write_set"]:
        exact_keys(row, {"key", "predecessor"}, "effect_manifest.resource_key")
    exact_keys(manifest["resource_profile"], {"adapter_id", "adapter_version", "resource_profile_id",
                                              "contract", "externalization_pq", "endpoint_pq_key_hash"},
               "effect_manifest.resource_profile")
    close_requirements(manifest["required_guarantees"], "effect_manifest.required_guarantees")
    fence = manifest["fence"]
    if fence.get("kind") == "protocol_height":
        exact_keys(fence, {"kind", "configuration_hash", "minimum_height", "maximum_height"}, "effect_manifest.fence")
    elif fence.get("kind") == "authority_epoch":
        exact_keys(fence, {"kind", "authority_snapshot_hash", "authority_epoch", "expires_at_height"}, "effect_manifest.fence")
    else:
        raise AssertionError("unknown effect fence")
    reconciliation = manifest["reconciliation"]
    if reconciliation.get("kind") == "lookup_by_idempotency_key":
        exact_keys(reconciliation, {"kind", "maximum_observations"}, "effect_manifest.reconciliation")
    elif reconciliation.get("kind") == "no_safe_reconciliation":
        exact_keys(reconciliation, {"kind"}, "effect_manifest.reconciliation")
    else:
        raise AssertionError("unknown reconciliation policy")

    snapshot = receipt["configuration_snapshot"]
    exact_keys(snapshot, {"network_id", "configuration_hash", "epoch", "key_root",
                          "snapshot_height", "key_root_votes"}, "receipt.configuration_snapshot")
    for vote in snapshot["key_root_votes"]:
        exact_keys(vote, {"member_id", "signature_base64"}, "configuration_snapshot.vote")
    consequence = receipt["consequence"]
    exact_keys(consequence, {"manifest_root", "intent_root", "execution_root", "outcome_root",
                             "reconciliation_root", "resource_record", "externalization_evidence"},
               "receipt.consequence")
    exact_keys(consequence["resource_record"], {"resource_id", "idempotency_key", "request_root",
                                                "predecessor_root", "outcome_root", "mutation_sequence",
                                                "evidence", "evidence_hash"}, "consequence.resource_record")
    exact_keys(consequence["externalization_evidence"], {"schema_version", "algorithm",
                                                         "endpoint_public_key_base64", "signature_base64"},
               "consequence.externalization_evidence")
    close_economic_proof(receipt["economic_proof"])
    for anchor in receipt["requested_anchors"]:
        exact_keys(anchor, {"anchor_ref", "anchor_hash"}, "receipt.requested_anchor")
    for anchor in trust["required_anchors"]:
        exact_keys(anchor, {"anchor_ref", "anchor_hash"}, "trust.required_anchor")
    for transform in receipt["transformation_trace"]:
        exact_keys(transform, {"rule", "theorem_id", "evidence_hash"}, "receipt.transformation")
    exact_keys(receipt["signature"], {"algorithm", "public_key_base64", "signature_base64"}, "receipt.signature")


def close_seal_key(key, label):
    exact_keys(key, {"scope", "key_index", "signature_suite", "public_key",
                     "predecessor_key_commitment"}, label)
    exact_keys(key["scope"], {"network_id", "configuration_id", "epoch", "conflict_domain_id",
                              "member_id", "member_index"}, label + ".scope")


def close_economic_proof(package):
    assert package is not None, "complete profile requires economic proof"
    exact_keys(package, {"evidence", "snapshot", "claimed"}, "receipt.economic_proof")
    evidence, snapshot, claim = package["evidence"], package["snapshot"], package["claimed"]
    exact_keys(evidence, {"schema_version", "configuration_hash", "behavior", "evidence_predicate_hash",
                          "evidence_hash", "implicated_members", "challenge_horizon_end"}, "economic.evidence")
    exact_keys(snapshot, {"schema_version", "snapshot_height", "configuration_hash", "bonds"}, "economic.snapshot")
    for bond in snapshot["bonds"]:
        exact_keys(bond, {"bond_id", "collateral_id", "owner_member_hash", "asset_id_hash",
                          "amount_base_units", "exclusive_configuration_hash", "locked_from",
                          "locked_until", "challenge_horizon_end", "evidence_predicate_hash",
                          "slashing_contract_hash", "active_encumbrance_hashes", "withdrawal_pending"},
                   "economic.bond")
    exact_keys(claim, {"schema_version", "asset_id_hash", "amount_base_units", "configuration_hash",
                       "collateral_set_hash", "bond_snapshot_root", "snapshot_height", "locked_until",
                       "challenge_horizon_end", "evidence_predicate", "evidence_predicate_hash",
                       "slashing_contract_hash", "valuation_assumptions"}, "economic.claim")
    if claim["valuation_assumptions"] is not None:
        exact_keys(claim["valuation_assumptions"], {"quote_asset_id_hash", "oracle_profile_hash",
                                                    "observed_at", "valid_until", "price_numerator",
                                                    "price_denominator"}, "economic.valuation_assumptions")


def as_bytes(value, expected=None):
    result = bytes(value)
    if expected is not None:
        assert len(result) == expected, f"expected {expected} bytes, got {len(result)}"
    return result


def account_id(suite, public_key):
    return hashlib.sha256(
        ACCOUNT_ID_DOMAIN + int(suite).to_bytes(4, "big", signed=True) + public_key
    ).digest()


def compact(value):
    assert 0 <= value < (1 << 30), "unsupported SCALE compact length"
    if value < 1 << 6:
        return bytes([value << 2])
    if value < 1 << 14:
        return ((value << 2) | 1).to_bytes(2, "little")
    return ((value << 2) | 2).to_bytes(4, "little")


def scale_vec(value):
    value = bytes(value)
    return compact(len(value)) + value


def scale_scope(scope):
    return b"".join([
        as_bytes(scope["network_id"], 32),
        as_bytes(scope["configuration_hash"], 32),
        int(scope["epoch"]).to_bytes(8, "little"),
        as_bytes(scope["initiator"], 32),
        as_bytes(scope["responder"], 32),
        as_bytes(scope["initiator_transport_binding"], 32),
        as_bytes(scope["responder_transport_binding"], 32),
    ])


def scale_client_hello(hello, include_signature=True):
    signature = hello["signature"] if include_signature else []
    return b"".join([
        int(hello["protocol_version"]).to_bytes(2, "little"),
        int(hello["schema_version"]).to_bytes(2, "little"),
        scale_scope(hello["scope"]),
        as_bytes(hello["nonce"], 32),
        scale_vec(hello["kem_public_key"]),
        int(hello["identity_suite"]).to_bytes(4, "little", signed=True),
        scale_vec(hello["identity_public_key"]),
        scale_vec(signature),
    ])


def scale_server_hello(server, include_signature=True):
    signature = server["signature"] if include_signature else []
    return b"".join([
        int(server["protocol_version"]).to_bytes(2, "little"),
        int(server["schema_version"]).to_bytes(2, "little"),
        as_bytes(server["client_hello_hash"], 32),
        as_bytes(server["nonce"], 32),
        scale_vec(server["kem_ciphertext"]),
        int(server["identity_suite"]).to_bytes(4, "little", signed=True),
        scale_vec(server["identity_public_key"]),
        scale_vec(signature),
    ])


def scale_client_finish(finish, include_signature=True):
    signature = finish["signature"] if include_signature else []
    return b"".join([
        int(finish["protocol_version"]).to_bytes(2, "little"),
        int(finish["schema_version"]).to_bytes(2, "little"),
        as_bytes(finish["transcript_hash"], 32),
        as_bytes(finish["key_confirmation"], 32),
        scale_vec(signature),
    ])


def scale_channel_evidence(evidence, include_attestations=True):
    initiator = evidence["initiator_attestation_signature"] if include_attestations else []
    responder = evidence["responder_attestation_signature"] if include_attestations else []
    return b"".join([
        int(evidence["protocol_version"]).to_bytes(2, "little"),
        int(evidence["schema_version"]).to_bytes(2, "little"),
        scale_vec(evidence["profile"]),
        scale_client_hello(evidence["client_hello"]),
        scale_server_hello(evidence["server_hello"]),
        scale_client_finish(evidence["client_finish"]),
        as_bytes(evidence["protected_payload_hash"], 32),
        scale_vec(initiator),
        scale_vec(responder),
    ])


def scale_seal_scope(scope):
    return b"".join([
        as_bytes(scope["network_id"], 32),
        as_bytes(scope["configuration_id"], 32),
        int(scope["epoch"]).to_bytes(8, "little"),
        as_bytes(scope["conflict_domain_id"], 32),
        as_bytes(scope["member_id"], 32),
        int(scope["member_index"]).to_bytes(4, "little"),
    ])


def scale_seal_key(key):
    return b"".join([
        scale_seal_scope(key["scope"]),
        int(key["key_index"]).to_bytes(8, "little"),
        int(key["signature_suite"]).to_bytes(4, "little", signed=True),
        scale_vec(key["public_key"]),
        as_bytes(key["predecessor_key_commitment"], 32),
    ])


def scale_seal_manifest(manifest):
    entries = b"".join(
        scale_seal_key(entry["initial_key"])
        + as_bytes(entry["initial_key_commitment"], 32)
        for entry in manifest["entries"]
    )
    return int(manifest["schema_version"]).to_bytes(2, "little") + compact(len(manifest["entries"])) + entries


def oracle_verify(oracle, command, public_key, signature, message):
    subprocess.run([
        str(oracle), command,
        base64.b64encode(public_key).decode(),
        base64.b64encode(signature).decode(),
        base64.b64encode(message).decode(),
    ], check=True, capture_output=True)


def verify_runtime_finality(bundle, oracle):
    assert bundle["schema_version"] == "ioi.foundations.receipt-proof-bundle.v3"
    assert bundle["bundle_domain"] == bundle["schema_version"]
    bundle_preimage = dict(bundle); bundle_preimage.pop("bundle_hash")
    assert sha(bundle_preimage) == bundle["bundle_hash"], "runtime bundle hash mismatch"
    checkpoint = bundle["checkpoint"]
    certificate = checkpoint["finality_certificate"]
    checkpoint_preimage = dict(checkpoint)
    checkpoint_preimage.pop("body_hash"); checkpoint_preimage.pop("finality_certificate")
    assert sha(checkpoint_preimage) == checkpoint["body_hash"], "checkpoint hash mismatch"
    assert checkpoint["body_hash"] == certificate["checkpoint_hash"]
    certificate_preimage = dict(certificate)
    certificate_preimage.pop("body_hash"); certificate_preimage.pop("signature")
    assert sha(certificate_preimage) == certificate["body_hash"], "finality certificate hash mismatch"
    assert certificate["schema_version"] == "ioi.finality-certificate.v2"
    assert certificate["certificate_domain"] == certificate["schema_version"]
    assert certificate["signature_suite"] == "ml-dsa-44"
    message = (certificate["schema_version"] + "\0" + certificate["body_hash"]).encode()
    oracle_verify(oracle, "verify-ml-dsa-44", bytes.fromhex(certificate["issuer_public_key"]),
                  bytes.fromhex(certificate["signature"]), message)
    trusted = bundle["trusted_issuer"]
    assert trusted["issuer_public_key"] == certificate["issuer_public_key"]
    assert trusted["issuer_key_id"] == certificate["issuer_key_id"]
    manifest = checkpoint["availability_manifest"]
    manifest_preimage = dict(manifest); manifest_preimage.pop("manifest_hash")
    assert sha(manifest_preimage) == manifest["manifest_hash"]
    assert manifest["manifest_hash"] == checkpoint["availability_manifest_hash"]
    for material in bundle["operations"] + bundle["receipts"]:
        assert sha(material["body"]) == material["body_hash"], "runtime material hash mismatch"
    evidence = certificate["hash_async_evidence"]
    assert evidence["schema_version"] == "ioi.native-aft-hash-async-evidence.v1"
    assert evidence["post_quantum"] is True
    assert evidence["private_threshold_setup"] is False
    assert evidence["private_authenticated_channels_required"] is True
    assert evidence["pq_authenticated_channels_required"] is True
    assert evidence["fault_model"] == "static_byzantine_f_lt_n_over_3"
    members = []
    for member in evidence["members"]:
        assert member["signature_suite"] == "ml-dsa-44"
        public = bytes.fromhex(member["public_key"])
        members.append((account_id(-17, public), public))
    assert members == sorted(members) and 2 <= len(members) <= 128
    assurance = certificate["assurance"]["achieved"]
    assert assurance["crypto"]["consensus_pq"] is True
    assert assurance["availability"]["publication_retrievable"] is True
    return members


def derive_runtime_vector(bundle, members, configuration_hash):
    """Derive the complete hash-async runtime vector without trusting its claim."""
    checkpoint = bundle["checkpoint"]
    certificate = checkpoint["finality_certificate"]
    evidence = certificate["hash_async_evidence"]
    n = len(members)
    f = (n - 1) // 3
    assert n >= 4 and n == 3 * f + 1, "hash-async committee is not exact n=3f+1"
    q = 2 * f + 1
    conflict_hash = hashlib.sha256(
        CONFLICT_DOMAIN + checkpoint["domain_id"].encode()
    ).digest()
    availability = checkpoint["availability_manifest_hash"]
    assert availability.startswith("sha256:") and len(availability) == 71
    availability_hash = bytes.fromhex(availability[7:])
    vector = {
        "schema_version": "v1",
        "safety": {
            "model": "quorum_intersection_bft",
            "finality_rank": "LiveTierBft",
            "committee_n": n,
            "fault_bound_f": f,
            "quorum_q": q,
            "configuration_hash": configuration_hash,
            "conflict_domain_hash": list(conflict_hash),
        },
        "liveness": {
            "termination": "randomized_asynchronous",
            "network": "asynchronous_private_authenticated_channels",
            "adversary": "static_byzantine",
            "committee_n": n,
            "fault_bound_f": f,
            "private_authenticated_channels": True,
        },
        "crypto": {
            "consensus_pq": evidence["post_quantum"],
            "channel_pq": False,
            "externalization_pq": False,
            "end_to_end_pq": False,
            "private_threshold_setup": evidence["private_threshold_setup"],
            "primitive_suites": ["unresolved", "sha256", "ml_dsa44", "pq_authenticated_channel"],
        },
        "accountability": "transferable",
        "availability": {
            "publication_retrievable": True,
            "custody_threshold": q,
            "retention_horizon": None,
        },
        "externalization": {
            "mode": "not_claimed",
            "at_most_once": False,
            "adapter_profile_hash": None,
        },
        "slashable_collateral": None,
        "measured_latency": None,
        "assumptions": ["A1", "A5"],
        "theorem_ids": ["T4a", "T6"],
        "certificate_profiles": ["HashAsyncOrderingCert"],
        "constituent_hashes": sorted_unique([
            list(digest(evidence)), list(availability_hash),
        ]),
        "transformation_hashes": [],
    }
    expected_requirements = {
        "minimum_finality_rank": "LiveTierBft",
        "configuration_hash": configuration_hash,
        "conflict_domain_hash": list(conflict_hash),
        "require_consensus_pq": True,
        "require_channel_pq": False,
        "require_externalization_pq": False,
        "require_end_to_end_pq": False,
        "require_no_private_threshold_setup": True,
        "minimum_accountability": None,
        "require_publication_retrievable": True,
        "minimum_externalization": None,
        "require_at_most_once": False,
    }
    envelope = certificate["assurance"]
    assert envelope["schema_version"] == "ioi.runtime-assurance.v1"
    assert envelope["requirements"] == expected_requirements, "runtime assurance requirements mismatch"
    assert envelope["transformations"] == [], "runtime assurance transformations unsupported"
    assert envelope["achieved"] == vector, "runtime achieved vector differs from verified evidence"
    commitment = "sha256:" + hashlib.sha256(GUARANTEE_VECTOR_DOMAIN + canonical(vector)).hexdigest()
    assert envelope["achieved_commitment"] == commitment, "runtime achieved commitment mismatch"
    return vector


def sorted_unique(values):
    """Rust BTreeSet wire form for strings or fixed-size byte arrays."""
    return sorted({canonical(value): value for value in values}.values())


def enum_set(values, declaration_order):
    unique = set(values)
    assert unique <= set(declaration_order), "unknown enum-set value"
    return [value for value in declaration_order if value in unique]


def derive_achieved_vector(base, members, channel_hash, seal_hash, consequence_hash,
                           profile_root, claim, proof_root):
    """Reproduce the Rust verifier's complete coordinate derivation.

    This intentionally returns the entire vector. Comparing only headline
    coordinates would allow a validly re-enveloped receipt to substitute
    theorem IDs, constituent roots, assumptions, or another ignored field.
    """
    achieved = copy.deepcopy(base)
    achieved["crypto"]["channel_pq"] = True
    achieved["externalization"] = {
        "mode": "idempotency_register",
        "at_most_once": True,
        "adapter_profile_hash": list(profile_root),
    }
    achieved["crypto"]["externalization_pq"] = True
    achieved["safety"].update({
        "model": "unanimous_all_but_one",
        "finality_rank": "SealedAllButOne",
        "committee_n": len(members),
        "fault_bound_f": len(members) - 1,
        "quorum_q": len(members),
    })
    achieved["accountability"] = "full_configuration"
    achieved["certificate_profiles"] = enum_set(
        achieved["certificate_profiles"] + ["PqUnanimousBoundaryClose"],
        ["LiveQuorumCert", "ClassicalSignedLiveQuorumCert", "PqLiveQuorumCert",
         "HashAsyncOrderingCert", "GuardianCommitteeCert", "WitnessCert", "ObserverCert",
         "UnanimousBoundaryClose", "PqUnanimousBoundaryClose", "AnchoredBoundaryClose",
         "PqAnchoredBoundaryClose", "HashPcdReference", "RegenesisRoot"],
    )
    achieved["crypto"]["primitive_suites"] = enum_set(
        achieved["crypto"]["primitive_suites"] + ["hash_based_signature"],
        ["unresolved", "sha256", "ed25519", "bls12381", "ml_dsa44",
         "hash_based_signature", "pq_authenticated_channel",
         "classical_authenticated_channel"],
    )
    if (achieved["crypto"]["consensus_pq"]
            and achieved["crypto"]["channel_pq"]
            and achieved["crypto"]["externalization_pq"]):
        achieved["crypto"]["primitive_suites"] = [
            value for value in achieved["crypto"]["primitive_suites"]
            if value != "unresolved"
        ]
    achieved["crypto"]["end_to_end_pq"] = (
        achieved["crypto"]["consensus_pq"]
        and achieved["crypto"]["channel_pq"]
        and achieved["crypto"]["externalization_pq"]
    )
    achieved["constituent_hashes"] = sorted_unique(
        achieved["constituent_hashes"]
        + [list(channel_hash), list(seal_hash), list(consequence_hash), list(proof_root)]
    )
    achieved["theorem_ids"] = sorted_unique(
        achieved["theorem_ids"] + ["T12", "T1", "T7", "T10", "T11"]
    )
    valuation = claim["valuation_assumptions"]
    achieved["slashable_collateral"] = {
        "asset_id_hash": claim["asset_id_hash"],
        "amount_base_units": claim["amount_base_units"],
        "collateral_set_hash": claim["collateral_set_hash"],
        "bond_snapshot_root": claim["bond_snapshot_root"],
        "locked_until": claim["locked_until"],
        "evidence_rule_hash": claim["evidence_predicate_hash"],
        "slashing_contract_hash": claim["slashing_contract_hash"],
        "valuation_assumptions_hash": (
            None if valuation is None else list(domain_digest(ECONOMIC_DOMAIN, valuation))
        ),
    }
    return achieved


def verify_channel_coverage(coverage, finality_hash, members, oracle):
    assert coverage["schema_version"] == "ioi.aft.pq-channel-coverage.v1"
    assert as_bytes(coverage["protected_finality_hash"], 32) == finality_hash
    member_map = dict(members)
    expected_pairs = {(left[0], right[0]) for i, left in enumerate(members) for right in members[i + 1:]}
    observed = set()
    for session in coverage["sessions"]:
        assert session["protocol_version"] == session["schema_version"] == 1
        assert as_bytes(session["profile"]) == CHANNEL_PROFILE
        assert as_bytes(session["protected_payload_hash"], 32) == finality_hash
        hello, server, finish = session["client_hello"], session["server_hello"], session["client_finish"]
        scope = hello["scope"]
        assert as_bytes(scope["network_id"]) == as_bytes(coverage["network_id"])
        assert as_bytes(scope["configuration_hash"]) == as_bytes(coverage["configuration_hash"])
        assert scope["epoch"] == coverage["epoch"]
        initiator, responder = as_bytes(scope["initiator"], 32), as_bytes(scope["responder"], 32)
        assert initiator != responder
        initiator_public = as_bytes(hello["identity_public_key"], 1312)
        responder_public = as_bytes(server["identity_public_key"], 1312)
        assert member_map[initiator] == initiator_public and member_map[responder] == responder_public
        assert hello["identity_suite"] == server["identity_suite"] == -17
        assert len(hello["kem_public_key"]) == 1217 and len(server["kem_ciphertext"]) == 1121
        hello_message = scale_vec(CLIENT_HELLO_DOMAIN) + scale_client_hello(hello, False)
        oracle_verify(oracle, "verify-ml-dsa-44", initiator_public, as_bytes(hello["signature"]), hello_message)
        hello_hash = hashlib.sha256(scale_client_hello(hello)).digest()
        assert as_bytes(server["client_hello_hash"]) == hello_hash
        server_message = scale_vec(SERVER_HELLO_DOMAIN) + scale_server_hello(server, False)
        oracle_verify(oracle, "verify-ml-dsa-44", responder_public, as_bytes(server["signature"]), server_message)
        transcript = hashlib.sha256(scale_vec(CHANNEL_PROFILE) + scale_client_hello(hello) + scale_server_hello(server)).digest()
        assert as_bytes(finish["transcript_hash"]) == transcript
        finish_message = scale_vec(CLIENT_FINISH_DOMAIN) + scale_client_finish(finish, False)
        oracle_verify(oracle, "verify-ml-dsa-44", initiator_public, as_bytes(finish["signature"]), finish_message)
        completion_message = scale_vec(CHANNEL_COMPLETION_DOMAIN) + scale_channel_evidence(session, False)
        oracle_verify(oracle, "verify-ml-dsa-44", initiator_public,
                      as_bytes(session["initiator_attestation_signature"]), completion_message)
        oracle_verify(oracle, "verify-ml-dsa-44", responder_public,
                      as_bytes(session["responder_attestation_signature"]), completion_message)
        pair = tuple(sorted((initiator, responder)))
        assert pair not in observed, "duplicate PQ channel pair"
        observed.add(pair)
    assert observed == expected_pairs, "incomplete PQ channel graph"
    return digest(coverage)


def verify_terminal_seal(receipt, finality_hash, members, manifest_root, oracle):
    snapshot, seal = receipt["configuration_snapshot"], receipt["terminal_seal"]
    manifest = seal["key_manifest"]
    assert seal["schema_version"] == "ioi.aft.terminal-seal.v1"
    assert manifest["schema_version"] == 1 and len(manifest["entries"]) == len(members)
    for entry in manifest["entries"]:
        key = entry["initial_key"]
        assert key["signature_suite"] == -301 and len(key["public_key"]) == 32
        assert as_bytes(entry["initial_key_commitment"]) == hashlib.sha256(SEAL_KEY_DOMAIN + scale_seal_key(key)).digest()
    key_root = hashlib.sha256(SEAL_MANIFEST_DOMAIN + scale_seal_manifest(manifest)).digest()
    assert key_root == as_bytes(snapshot["key_root"])
    vote_message = CONFIGURATION_VOTE_DOMAIN + canonical([
        snapshot["network_id"], snapshot["configuration_hash"], snapshot["epoch"],
        snapshot["key_root"], snapshot["snapshot_height"],
    ])
    assert len(snapshot["key_root_votes"]) == len(members)
    for vote, (member, public) in zip(snapshot["key_root_votes"], members):
        assert as_bytes(vote["member_id"]) == member
        oracle_verify(oracle, "verify-ml-dsa-44", public,
                      base64.b64decode(vote["signature_base64"]), vote_message)
    consequence = receipt["consequence"]
    seal_root = hashlib.sha256(canonical([
        list(TERMINAL_ROOT_DOMAIN), list(finality_hash), list(manifest_root),
        consequence["intent_root"], consequence["execution_root"],
        consequence["outcome_root"], consequence["reconciliation_root"],
    ])).digest()
    conflict = hashlib.sha256(
        CONFLICT_DOMAIN + receipt["effect_manifest"]["conflict_domain_id"].encode()
    ).digest()
    assert len(seal["shares"]) == len(members)
    for index, (share, entry, (member, _)) in enumerate(zip(seal["shares"], manifest["entries"], members)):
        key, scope = share["current_key"], share["current_key"]["scope"]
        assert key == entry["initial_key"] and share["protocol_version"] == share["schema_version"] == 2
        assert share["seal_slot"] == key["key_index"] == 0
        assert as_bytes(scope["member_id"]) == member and scope["member_index"] == index
        assert as_bytes(scope["network_id"]) == as_bytes(snapshot["network_id"])
        assert as_bytes(scope["configuration_id"]) == as_bytes(snapshot["configuration_hash"])
        assert scope["epoch"] == snapshot["epoch"] and as_bytes(scope["conflict_domain_id"]) == conflict
        assert as_bytes(share["seal_root"]) == seal_root and any(share["next_key_commitment"])
        message = b"".join([
            SEAL_SHARE_DOMAIN,
            int(share["protocol_version"]).to_bytes(2, "little"),
            int(share["schema_version"]).to_bytes(2, "little"),
            scale_seal_key(key), int(share["seal_slot"]).to_bytes(8, "little"),
            as_bytes(share["seal_root"], 32), as_bytes(share["next_key_commitment"], 32),
        ])
        oracle_verify(oracle, "verify-slh-dsa-sha2-128s", as_bytes(key["public_key"]),
                      as_bytes(share["signature"]), message)
    return digest(seal), conflict


def verify_golden(root):
    vector = json.loads((root / "golden/canonical-v1.json").read_text())
    actual = hashlib.sha256(vector["canonical_json"].encode()).hexdigest()
    assert actual == vector["sha256"], "canonical golden hash mismatch"
    economic = json.loads((root / "golden/economic-v1.json").read_text())
    seen_bonds, seen_lots, floor = set(), set(), 0
    for bond in economic["bonds"]:
        assert bond["bond_id"] not in seen_bonds, "duplicate bond"
        assert bond["collateral_id"] not in seen_lots, "duplicate collateral"
        seen_bonds.add(bond["bond_id"])
        seen_lots.add(bond["collateral_id"])
        if bond["eligible"]:
            floor += int(bond["amount"])
    assert str(floor) == economic["expected_floor"], "economic floor mismatch"
    return {"canonical_sha256": actual, "economic_floor": str(floor)}


def verify_external_trust(receipt, trust):
    assert trust["schema_version"] == TRUST_SCHEMA, "unsupported external trust schema"
    snapshot = receipt["configuration_snapshot"]
    assert any(trust["network_id"]), "zero trusted network"
    assert any(trust["configuration_hash"]), "zero trusted configuration"
    assert any(trust["terminal_key_root"]), "zero trusted terminal key root"
    assert snapshot["network_id"] == trust["network_id"], "untrusted network"
    assert snapshot["configuration_hash"] == trust["configuration_hash"], "untrusted configuration"
    assert snapshot["epoch"] == trust["epoch"], "untrusted epoch"
    assert snapshot["key_root"] == trust["terminal_key_root"], "untrusted terminal key root"
    allowed = trust["allowed_receipt_public_keys_base64"]
    assert allowed and receipt["signature"]["public_key_base64"] in allowed, "untrusted receipt signer"
    receipt_anchors = {row["anchor_ref"]: row["anchor_hash"] for row in receipt["requested_anchors"]}
    trusted_anchors = {row["anchor_ref"]: row["anchor_hash"] for row in trust["required_anchors"]}
    assert len(receipt_anchors) == len(receipt["requested_anchors"]), "duplicate receipt anchor"
    assert len(trusted_anchors) == len(trust["required_anchors"]), "duplicate trusted anchor"
    assert receipt_anchors == trusted_anchors and receipt_anchors, "external anchor mismatch"
    required = trust["required_guarantees"]
    assert required["configuration_hash"] == trust["configuration_hash"], "trust policy does not pin configuration"


def requirement_satisfied(achieved, required):
    rank = {None: 0, "Ordered": 1, "Available": 2, "Finalized": 3, "SealedAllButOne": 4}
    accountability = {None: 0, "none": 0, "individual": 1, "quorum_intersection": 2,
                      "full_configuration": 3}
    externalization = {None: 0, "authorization_only": 0, "reconciled": 1,
                       "idempotency_register": 2, "atomic_resource": 3}
    safety = achieved["safety"]
    crypto = achieved["crypto"]
    availability = achieved["availability"]
    consequence = achieved["externalization"]
    if rank[safety["finality_rank"]] < rank[required["minimum_finality_rank"]]: return False
    for name in ("configuration_hash", "conflict_domain_hash"):
        if required[name] is not None and safety[name] != required[name]: return False
    for name in ("consensus_pq", "channel_pq", "externalization_pq", "end_to_end_pq"):
        if required["require_" + name] and not crypto[name]: return False
    if required["require_no_private_threshold_setup"] and crypto["private_threshold_setup"]: return False
    if accountability[achieved["accountability"]] < accountability[required["minimum_accountability"]]: return False
    if required["require_publication_retrievable"] and not availability["publication_retrievable"]: return False
    if externalization[consequence["mode"]] < externalization[required["minimum_externalization"]]: return False
    if required["require_at_most_once"] and not consequence["at_most_once"]: return False
    floor = required.get("minimum_slashable_collateral")
    if floor is not None:
        actual = achieved["slashable_collateral"]
        if actual is None or actual["asset_id_hash"] != floor["asset_id_hash"]: return False
        if int(actual["amount_base_units"]) < int(floor["minimum_amount_base_units"]): return False
    return True


def verify_receipt(path, trust_path, pq_oracle):
    raw = path.read_bytes()
    receipt = json.loads(raw)
    trust_raw = trust_path.read_bytes()
    trust = json.loads(trust_raw)
    assert trust_raw == canonical(trust), "external trust policy is not canonical"
    assert raw == canonical(receipt), "receipt is not canonical"
    close_portable_schema(receipt, trust)
    assert receipt["schema_version"] == SCHEMA, "unsupported schema"
    assert receipt["verifier_profile"] == PROFILE, "unsupported verifier"
    verify_external_trust(receipt, trust)
    preimage = dict(receipt)
    preimage.pop("receipt_hash")
    preimage.pop("signature")
    assert sha(preimage) == receipt["receipt_hash"], "receipt hash mismatch"
    finality_bundle = receipt["finality_bundle"]
    members = verify_runtime_finality(finality_bundle, pq_oracle)
    base_achieved = derive_runtime_vector(
        finality_bundle, members, receipt["configuration_snapshot"]["configuration_hash"]
    )
    finality_hash = digest(finality_bundle)
    channel_hash = verify_channel_coverage(
        receipt["channel_coverage"], finality_hash, members, pq_oracle
    )

    manifest, consequence = receipt["effect_manifest"], receipt["consequence"]
    profile = manifest["resource_profile"]
    assert profile["contract"] in ("atomic_put_if_absent", "atomic_compare_and_set")
    assert profile["externalization_pq"] is True
    profile_root = domain_digest(RESOURCE_PROFILE_DOMAIN, profile)
    manifest_root = domain_digest(EFFECT_MANIFEST_DOMAIN, manifest)
    assert as_bytes(consequence["manifest_root"]) == manifest_root, "manifest root mismatch"
    assert manifest["intent_root"] == consequence["intent_root"], "intent mismatch"
    record = consequence["resource_record"]
    assert manifest["resource_id"] == record["resource_id"], "resource mismatch"
    assert manifest["idempotency_key"] == record["idempotency_key"], "key mismatch"
    assert manifest["request_root"] == record["request_root"], "request mismatch"
    assert manifest["predecessor_root"] == record["predecessor_root"], "predecessor mismatch"
    assert manifest["expected_outcome_root"] == record["outcome_root"] == consequence["outcome_root"], "outcome mismatch"
    assert receipt["policy"] == manifest["required_guarantees"], "policy mismatch"
    endpoint = consequence["externalization_evidence"]
    assert endpoint["schema_version"] == "ioi.aft.pq-externalization-evidence.v1"
    assert endpoint["algorithm"] == "ml-dsa-44"
    endpoint_public = base64.b64decode(endpoint["endpoint_public_key_base64"])
    assert account_id(-17, endpoint_public) == as_bytes(profile["endpoint_pq_key_hash"])
    endpoint_message = EXTERNALIZATION_SIG_DOMAIN + canonical([
        list(manifest_root), list(profile_root), record, consequence["intent_root"],
        consequence["execution_root"], consequence["outcome_root"],
        consequence["reconciliation_root"],
    ])
    oracle_verify(pq_oracle, "verify-ml-dsa-44", endpoint_public,
                  base64.b64decode(endpoint["signature_base64"]), endpoint_message)

    seal_hash, conflict_hash = verify_terminal_seal(
        receipt, finality_hash, members, manifest_root, pq_oracle
    )
    assert conflict_hash == as_bytes(receipt["policy"]["conflict_domain_hash"])
    assert as_bytes(receipt["configuration_snapshot"]["configuration_hash"]) == as_bytes(
        receipt["policy"]["configuration_hash"]
    )
    assert as_bytes(receipt["channel_coverage"]["configuration_hash"]) == as_bytes(
        receipt["configuration_snapshot"]["configuration_hash"]
    )
    transforms = [(row["rule"], row["theorem_id"]) for row in receipt["transformation_trace"]]
    allowed = [
        ("establish_channel_pq_from_transcript_verification", "T12"),
        ("establish_safety_from_independent_proof", "T1"),
        ("establish_externalization_from_resource_proof", "T10"),
        ("establish_slashable_collateral_from_bond_proof", "T11"),
    ]
    assert transforms == allowed, "unknown or reordered transformation"
    consequence_hash = digest(consequence)
    for row, expected in zip(receipt["transformation_trace"][:3],
                             (channel_hash, seal_hash, consequence_hash)):
        assert as_bytes(row["evidence_hash"]) == expected, "transformation evidence mismatch"
    package = receipt["economic_proof"]
    evidence, snapshot, claim = package["evidence"], package["snapshot"], package["claimed"]
    assert evidence["behavior"] != "withholding_or_silence", "silence is unpriceable"
    assert evidence["configuration_hash"] == snapshot["configuration_hash"] == claim["configuration_hash"]
    assert snapshot["snapshot_height"] <= evidence["challenge_horizon_end"]
    seen_bonds, seen_lots, floor = set(), set(), 0
    covered, collateral_ids = set(), []
    common_asset, common_contract, minimum_lock = None, None, None
    for bond in snapshot["bonds"]:
        bond_id, lot_id = tuple(bond["bond_id"]), tuple(bond["collateral_id"])
        assert bond_id not in seen_bonds and lot_id not in seen_lots, "duplicate collateral"
        if seen_bonds:
            assert max(seen_bonds) < bond_id, "noncanonical bond order"
        seen_bonds.add(bond_id); seen_lots.add(lot_id); collateral_ids.append(bond["collateral_id"])
        assert not bond["active_encumbrance_hashes"] and not bond["withdrawal_pending"], "encumbered collateral"
        assert bond["locked_from"] <= snapshot["snapshot_height"] <= bond["locked_until"], "unlocked collateral"
        assert bond["locked_until"] >= evidence["challenge_horizon_end"], "expired collateral"
        assert bond["exclusive_configuration_hash"] == evidence["configuration_hash"]
        assert bond["evidence_predicate_hash"] == evidence["evidence_predicate_hash"]
        assert bond["challenge_horizon_end"] == evidence["challenge_horizon_end"]
        assert bond["owner_member_hash"] in evidence["implicated_members"]
        covered.add(tuple(bond["owner_member_hash"]))
        common_asset = bond["asset_id_hash"] if common_asset is None else common_asset
        common_contract = bond["slashing_contract_hash"] if common_contract is None else common_contract
        assert bond["asset_id_hash"] == common_asset and bond["slashing_contract_hash"] == common_contract
        minimum_lock = bond["locked_until"] if minimum_lock is None else min(minimum_lock, bond["locked_until"])
        floor += int(bond["amount_base_units"])
    assert covered == {tuple(value) for value in evidence["implicated_members"]}
    assert str(floor) == claim["amount_base_units"], "collateral floor mismatch"
    snapshot_root = domain_digest(BOND_SNAPSHOT_DOMAIN, snapshot)
    collateral_root = domain_digest(COLLATERAL_SET_DOMAIN, collateral_ids)
    assert as_bytes(claim["bond_snapshot_root"]) == snapshot_root
    assert as_bytes(claim["collateral_set_hash"]) == collateral_root
    assert claim["asset_id_hash"] == common_asset and claim["slashing_contract_hash"] == common_contract
    assert claim["locked_until"] == minimum_lock and claim["snapshot_height"] == snapshot["snapshot_height"]
    assert claim["challenge_horizon_end"] == evidence["challenge_horizon_end"]
    assert claim["evidence_predicate"] == evidence["behavior"]
    assert claim["evidence_predicate_hash"] == evidence["evidence_predicate_hash"]
    evidence_root = domain_digest(ACCOUNTABILITY_DOMAIN, evidence)
    assurance_root = domain_digest(ECONOMIC_DOMAIN, claim)
    proof_root = domain_digest(ECONOMIC_DOMAIN, [
        list(evidence_root), list(snapshot_root), list(assurance_root)
    ])
    assert as_bytes(receipt["transformation_trace"][3]["evidence_hash"]) == proof_root

    achieved, policy = receipt["claimed_achieved"], receipt["policy"]
    expected_achieved = derive_achieved_vector(
        base_achieved, members, channel_hash, seal_hash, consequence_hash,
        profile_root, claim, proof_root,
    )
    assert achieved == expected_achieved, "claimed guarantee vector differs from verified evidence"
    assert achieved["safety"]["model"] == "unanimous_all_but_one"
    assert achieved["safety"]["finality_rank"] == "SealedAllButOne"
    assert achieved["safety"]["committee_n"] == len(members)
    assert achieved["safety"]["fault_bound_f"] == len(members) - 1
    assert achieved["safety"]["quorum_q"] == len(members)
    assert achieved["safety"]["configuration_hash"] == policy["configuration_hash"]
    assert achieved["safety"]["conflict_domain_hash"] == policy["conflict_domain_hash"]
    assert achieved["accountability"] == "full_configuration"
    assert achieved["availability"]["publication_retrievable"] is True
    assert achieved["externalization"]["mode"] == "idempotency_register"
    assert achieved["externalization"]["at_most_once"] is True
    assert achieved["externalization"]["adapter_profile_hash"] == list(profile_root)
    for coordinate in ("consensus_pq", "channel_pq", "externalization_pq", "end_to_end_pq"):
        assert achieved["crypto"][coordinate] is True and policy["require_" + coordinate] is True
    assert achieved["crypto"]["private_threshold_setup"] is False
    assert policy["require_no_private_threshold_setup"] is True
    assert policy["minimum_accountability"] == "full_configuration"
    assert policy["minimum_externalization"] == "idempotency_register"
    assert policy["require_at_most_once"] is True
    assert policy["require_publication_retrievable"] is True
    assert requirement_satisfied(achieved, trust["required_guarantees"]), "external guarantee policy unsatisfied"
    signature = receipt["signature"]
    assert signature["algorithm"] == "ml-dsa-44", "unsupported signature algorithm"
    message = SIG_DOMAIN + receipt["receipt_hash"].encode()
    oracle_verify(pq_oracle, "verify-ml-dsa-44",
                  base64.b64decode(signature["public_key_base64"]),
                  base64.b64decode(signature["signature_base64"]), message)
    return {"accepted": True, "policy_satisfied": True,
            "economic_floor": str(floor), "verified_transformations": transforms}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--receipt", type=Path)
    parser.add_argument("--trust", type=Path)
    parser.add_argument("--pq-oracle", type=Path)
    parser.add_argument("--negative-dir", type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parent
    output = {"golden": verify_golden(root)}
    if args.receipt:
        assert args.pq_oracle and args.trust, "--pq-oracle and --trust are required with --receipt"
        output["receipt"] = verify_receipt(args.receipt, args.trust, args.pq_oracle)
    if args.negative_dir:
        assert args.pq_oracle, "--pq-oracle is required with --negative-dir"
        rejected = []
        for path in sorted(args.negative_dir.glob("validly-reenveloped-inner-mutation-*.json")):
            if path.name.endswith(".trust.json"):
                continue
            trust_path = path.with_name(path.stem + ".trust.json")
            assert trust_path.exists(), f"missing trust policy for {path.name}"
            try:
                verify_receipt(path, trust_path, args.pq_oracle)
            except Exception:
                rejected.append(path.name)
            else:
                raise AssertionError(f"negative receipt accepted: {path.name}")
        assert rejected, "negative receipt directory is empty"
        output["negative_receipts_rejected"] = rejected
    print(json.dumps(output, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(json.dumps({"accepted": False, "refusal": str(error)}, sort_keys=True), file=sys.stderr)
        sys.exit(1)
