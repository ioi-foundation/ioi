import assert from "node:assert/strict";
import test from "node:test";
import {
  buildC7GovernedEffectClaimManifest,
  GOVERNED_EFFECT_CLAIM_IDS,
  governedEffectClaimManifestHash,
  validateGovernedEffectClaimManifest,
} from "./governed-effect-claim-manifest.mjs";

const digest = (character) => `sha256:${character.repeat(64)}`;

function fixture() {
  const certificate = {
    certificate_hash: digest("a"),
    source: { commit: "900bc8ad640aaf18e091a13aae33204c104f51b6", daemon_binary_sha256: digest("b") },
    provider: { workload_readiness_proven: false, endpoint_ref: "akash-endpoint://one" },
    proposal: { admission_receipt_ref: "proposal-admission://one", consumption_receipt_ref: "proposal-consumption://one" },
    journal: { outcome_root: digest("c") },
    durable: { terminal_reconciliation_receipt_ref: "provider-receipt://terminal" },
  };
  const verification = { ok: true };
  return { certificate, verification };
}

test("C7 claim manifest exhaustively distinguishes demonstrated claims and bounded nonclaims", () => {
  const { certificate, verification } = fixture();
  const manifest = buildC7GovernedEffectClaimManifest(certificate, verification, "2026-08-22T12:00:00Z");
  assert.deepEqual(manifest.claims.map(({ claim_id }) => claim_id), GOVERNED_EFFECT_CLAIM_IDS);
  assert.equal(manifest.claims.find(({ claim_id }) => claim_id === "logical_policy_mediation").status, "demonstrated");
  assert.equal(manifest.claims.find(({ claim_id }) => claim_id === "workload_bound_isolation_enforced").status, "not_demonstrated");
  assert.equal(manifest.claims.find(({ claim_id }) => claim_id === "third_party_verified").status, "not_demonstrated");
  assert.deepEqual(validateGovernedEffectClaimManifest(manifest, certificate, verification), { ok: true, failures: [] });
});

test("claim inflation cannot be made valid by resealing only the manifest", () => {
  const { certificate, verification } = fixture();
  const manifest = buildC7GovernedEffectClaimManifest(certificate, verification, "2026-08-22T12:00:00Z");
  const claim = manifest.claims.find(({ claim_id }) => claim_id === "worker_secret_non_possession_tested");
  claim.status = "demonstrated";
  claim.evidence_refs = ["evidence://invented/secret-isolation"];
  manifest.manifest_hash = governedEffectClaimManifestHash(manifest);
  const result = validateGovernedEffectClaimManifest(manifest, certificate, verification);
  assert.equal(result.ok, false);
  assert.ok(result.failures.includes("claim_inflated:worker_secret_non_possession_tested"));
});

test("demonstrated claims without durable evidence fail closed", () => {
  const { certificate, verification } = fixture();
  const manifest = buildC7GovernedEffectClaimManifest(certificate, verification, "2026-08-22T12:00:00Z");
  const claim = manifest.claims.find(({ claim_id }) => claim_id === "separate_verifier");
  claim.evidence_refs = [];
  manifest.manifest_hash = governedEffectClaimManifestHash(manifest);
  const result = validateGovernedEffectClaimManifest(manifest, certificate, verification);
  assert.equal(result.ok, false);
  assert.ok(result.failures.includes("demonstrated_claim_without_evidence"));
});

test("duplicate or incomplete claim vocabularies fail closed", () => {
  const { certificate, verification } = fixture();
  const manifest = buildC7GovernedEffectClaimManifest(certificate, verification, "2026-08-22T12:00:00Z");
  manifest.claims.pop();
  manifest.claims.push(structuredClone(manifest.claims[0]));
  manifest.manifest_hash = governedEffectClaimManifestHash(manifest);
  const result = validateGovernedEffectClaimManifest(manifest, certificate, verification);
  assert.equal(result.ok, false);
  assert.ok(result.failures.includes("claim_duplicate"));
  assert.ok(result.failures.includes("claim_vocabulary_incomplete"));
});
