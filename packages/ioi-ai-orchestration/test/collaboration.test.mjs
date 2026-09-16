// R-172 S3 — the collaboration composer's derivations are pinned against the REGISTERED contracts:
// the root member lists must equal the invariants' material fields, the registered positive
// fixtures must recompute under the package's own derivations, activation must be a projection of
// the acceptances, signatures must round-trip and verify only against the key of record, and the
// bundle must exclude every ref of an excluded context class.
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

import {
  BUNDLE_ROOT_MEMBERS,
  COLLABORATION_CONTRACTS,
  COLLABORATION_DOMAINS,
  DISCOVERY_ROOT_MEMBERS,
  PARTICIPATION_REQUEST_HASH_MEMBERS,
  buildParticipationRequest,
  deriveBundleRoot,
  deriveDiscoveryStateRoot,
  deriveParticipationRequestHash,
  deriveTermsAcceptanceMaterialHash,
  deriveTermsActivation,
  generateSigner,
  signMaterialHash,
  signerFromSeed,
  verifySignatureEnvelope,
  verifyStateBundle,
} from "../dist/index.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const schemas = path.resolve(here, "../../../docs/architecture/_meta/schemas");
const readJson = (rel) => JSON.parse(fs.readFileSync(path.join(schemas, rel), "utf8"));
const materialMembers = (invariantFile, ruleId) => {
  const rule = readJson(`invariants/${invariantFile}`).rules.find((r) => r.rule_id === ruleId);
  const { domain, ...members } = rule.expression.material_fields;
  return { domain: domain.value, members: Object.keys(members).sort() };
};

test("the root member lists are exactly the registered invariants' material fields", () => {
  const discovery = materialMembers("orchestration-discovery.v1.invariants.json", "orchestration_discovery.state_root.commits_publication");
  assert.equal(discovery.domain, COLLABORATION_DOMAINS.discoveryStateRoot);
  assert.deepEqual([...DISCOVERY_ROOT_MEMBERS].sort(), discovery.members);
  const request = materialMembers("orchestration-participation-request.v1.invariants.json", "orchestration_participation_request.request_hash.commits_request");
  assert.equal(request.domain, COLLABORATION_DOMAINS.participationRequestHash);
  assert.deepEqual([...PARTICIPATION_REQUEST_HASH_MEMBERS].sort(), request.members);
  const bundle = materialMembers("participant-state-bundle.v4.invariants.json", "participant_state_bundle.bundle_root.commits_bundle");
  assert.equal(bundle.domain, COLLABORATION_DOMAINS.bundleRoot);
  assert.deepEqual([...BUNDLE_ROOT_MEMBERS].sort(), bundle.members);
  for (const members of [DISCOVERY_ROOT_MEMBERS, PARTICIPATION_REQUEST_HASH_MEMBERS, BUNDLE_ROOT_MEMBERS]) {
    assert.ok(!members.includes("system_binding"), "a root never commits the seam-derived binding, whose payload root would contain the root");
  }
});

test("the registered positive fixtures recompute under the package's derivations", () => {
  const discovery = readJson("fixtures/orchestration-discovery-v1/positive-hosted-discoverable.json");
  assert.equal(deriveDiscoveryStateRoot(discovery), discovery.discovery_state_root);
  assert.notEqual(deriveDiscoveryStateRoot({ ...discovery, public_objective: "edited" }), discovery.discovery_state_root);
  const request = readJson("fixtures/orchestration-participation-request-v1/positive-submitted.json");
  assert.equal(deriveParticipationRequestHash(request), request.request_hash);
  const accepted = readJson("fixtures/orchestration-participation-request-v1/positive-accepted-revision.json");
  assert.equal(deriveParticipationRequestHash(accepted), accepted.request_hash, "the decision revision does not move the request hash");
  const bundle = readJson("fixtures/participant-state-bundle-v4/positive-hosted-export.json");
  assert.equal(deriveBundleRoot(bundle), bundle.bundle_root);
  const tampered = readJson("fixtures/participant-state-bundle-v4/negative-root-does-not-recompute.json");
  assert.notEqual(deriveBundleRoot(tampered), tampered.bundle_root);
});

test("activation is a projection of exact-root acceptances by every required party", () => {
  const terms = readJson("fixtures/collaboration-terms-envelope-v3/positive-active-unanimous.json");
  const derived = deriveTermsActivation(terms, terms.activation.acceptance_receipt_refs, terms.activation.activated_at);
  assert.deepEqual(derived, terms.activation);
  const pending = readJson("fixtures/collaboration-terms-envelope-v3/positive-proposed-awaiting-acceptance.json");
  assert.equal(deriveTermsActivation(pending, [], "2026-09-16T12:30:00Z"), null, "one required party missing: no activation");
  const wrongRoot = { ...terms, acceptances: terms.acceptances.map((a, i) => (i === 1 ? { ...a, terms_body_root: `sha256:${"9".repeat(64)}` } : a)) };
  assert.equal(deriveTermsActivation(wrongRoot, [], "2026-09-16T12:30:00Z"), null, "an acceptance over another root does not count");
  const extra = { ...terms, acceptances: [...terms.acceptances, { ...terms.acceptances[0], party_ref: "worker://uninvited" }] };
  assert.deepEqual(deriveTermsActivation(extra, [], "2026-09-16T12:30:00Z")?.accepted_party_refs, [...terms.activation.accepted_party_refs, "worker://uninvited"].sort(), "accepted parties are exactly the acceptors on record");
  assert.match(deriveTermsAcceptanceMaterialHash({ collaboration_terms_id: "terms://x", terms_body_root: terms.terms_body_root, party_ref: "worker://a", accepted_at: "2026-09-16T12:00:00Z" }), /^sha256:[0-9a-f]{64}$/u);
});

test("signatures round-trip, verify only against the key of record, and a seed-derived signer is deterministic", () => {
  const alloy = signerFromSeed("worker://independent-alloy-lab", "09".repeat(32));
  const again = signerFromSeed("worker://independent-alloy-lab", "09".repeat(32));
  assert.equal(alloy.publicKeyHex, again.publicKeyHex);
  assert.match(alloy.publicKeyHex, /^[0-9a-f]{64}$/u);
  const other = generateSigner("worker://replication-lab-two");
  const hash = `sha256:${"a".repeat(64)}`;
  const envelope = signMaterialHash(alloy, hash);
  assert.equal(envelope.signer_ref, "worker://independent-alloy-lab");
  assert.ok(verifySignatureEnvelope(envelope, hash));
  assert.ok(verifySignatureEnvelope(envelope, hash, alloy.publicKeyHex));
  assert.ok(!verifySignatureEnvelope(envelope, hash, other.publicKeyHex), "a declared key that is not the key of record does not verify");
  assert.ok(!verifySignatureEnvelope(envelope, `sha256:${"b".repeat(64)}`), "another material does not verify");
  assert.ok(!verifySignatureEnvelope({ ...envelope, signature: envelope.signature.replace(/^./u, envelope.signature[0] === "0" ? "1" : "0") }, hash));
});

test("an external party builds a request whose hash and signature the host can recompute; the bundle verifies offline and never carries an excluded ref", () => {
  const alloy = signerFromSeed("worker://independent-alloy-lab", "09".repeat(32));
  const request = buildParticipationRequest({
    participation_request_id: "participation-request://ioi/orchestration/demo/alloy-1",
    orchestration_ref: "app-scope://ioi-ai/objective/demo",
    discovery_ref: "discovery://ioi/orchestration/demo/1",
    coordination_topology: "hosted_admission",
    admission_owner_ref: "system://ioi/orchestration/demo",
    requester_system_ref: "domain://independent-alloy-lab",
    collaboration_terms_ref: "terms://ioi/orchestration/demo/1",
    collaboration_terms_root: `sha256:${"c".repeat(64)}`,
    terms_response: "accept",
    requested_at: "2026-09-16T12:00:00Z",
  }, alloy);
  assert.equal(request.requested_by_ref, "worker://independent-alloy-lab");
  assert.equal(request.status, "submitted");
  assert.equal(request.decision, null);
  assert.equal(request.request_hash, deriveParticipationRequestHash(request));
  assert.ok(verifySignatureEnvelope(request.signature, request.request_hash, alloy.publicKeyHex));
  assert.equal(request.contract_id, undefined);
  assert.equal(COLLABORATION_CONTRACTS.participation, "schema://ioi/applications/ioi-ai/orchestration-participation-request/v1");

  const host = generateSigner("system://ioi/orchestration/demo");
  const bundle = readJson("fixtures/participant-state-bundle-v4/positive-hosted-export.json");
  const signed = { ...bundle, signature: signMaterialHash(host, bundle.bundle_root) };
  assert.deepEqual(verifyStateBundle(signed, host.publicKeyHex), { ok: true, findings: [] });
  const foreign = { ...signed, signature: signMaterialHash(generateSigner("system://ioi/orchestration/demo"), bundle.bundle_root) };
  assert.equal(verifyStateBundle(foreign, host.publicKeyHex).ok, false, "another key claiming the host's name does not verify");
  const withDatabase = { ...signed, hosted_database_access_required: true };
  assert.ok(verifyStateBundle(withDatabase, host.publicKeyHex).findings.some((f) => /hosted_database_access_required/u.test(f)));
  const smuggled = { ...signed, portable_artifact_and_view_refs: [...signed.portable_artifact_and_view_refs, "artifact://smuggled"] };
  assert.ok(verifyStateBundle(smuggled, host.publicKeyHex).findings.some((f) => /bundle_root/u.test(f)));
});
