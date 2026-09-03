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
    assert receipt["schema_version"] == SCHEMA, "unsupported schema"
    assert receipt["verifier_profile"] == PROFILE, "unsupported verifier"
    verify_external_trust(receipt, trust)
    preimage = dict(receipt)
    preimage.pop("receipt_hash")
    preimage.pop("signature")
    assert sha(preimage) == receipt["receipt_hash"], "receipt hash mismatch"
    finality_bundle = receipt["finality_bundle"]
    members = verify_runtime_finality(finality_bundle, pq_oracle)
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
