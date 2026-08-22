import crypto from "node:crypto";
import { stableStringify } from "./c7-c8-certificate.mjs";

export const GOVERNED_EFFECT_CLAIM_IDS = Object.freeze([
  "governed_infrastructure_lifecycle",
  "workload_readiness",
  "workload_result_binding",
  "logical_policy_mediation",
  "workload_bound_isolation_enforced",
  "worker_secret_non_possession_tested",
  "separate_verifier",
  "independently_reproduced",
  "third_party_verified",
  "provider_neutrality",
  "bare_metal_placement",
]);

const hash = (value) => `sha256:${crypto.createHash("sha256").update(String(value)).digest("hex")}`;
const shaValue = (value) => /^sha256:[0-9a-f]{64}$/u.test(value || "");
const refValue = (value) => typeof value === "string" && /^[a-z][a-z0-9+.-]*:\/\/\S+$/u.test(value);

export function governedEffectClaimManifestHash(manifest) {
  const copy = structuredClone(manifest);
  delete copy.manifest_hash;
  return hash(stableStringify(copy));
}

function claim(claimId, demonstrated, evidenceRefs, limitationNote) {
  return {
    claim_id: claimId,
    status: demonstrated ? "demonstrated" : "not_demonstrated",
    evidence_refs: demonstrated ? evidenceRefs : [],
    limitation_note: limitationNote,
  };
}

export function expectedC7ClaimStatuses(certificate, verification) {
  return new Map([
    ["governed_infrastructure_lifecycle", true],
    ["workload_readiness", certificate?.provider?.workload_readiness_proven === true],
    ["workload_result_binding", false],
    ["logical_policy_mediation", true],
    ["workload_bound_isolation_enforced", false],
    ["worker_secret_non_possession_tested", false],
    ["separate_verifier", verification?.ok === true],
    ["independently_reproduced", false],
    ["third_party_verified", false],
    ["provider_neutrality", false],
    ["bare_metal_placement", false],
  ]);
}

export function buildC7GovernedEffectClaimManifest(certificate, verification, generatedAt = new Date().toISOString()) {
  const certificateId = String(certificate?.certificate_hash || "").replace(/^sha256:/u, "");
  const certificateRef = `certificate://c8/${certificateId}`;
  const status = expectedC7ClaimStatuses(certificate, verification);
  const claims = [
    claim("governed_infrastructure_lifecycle", status.get("governed_infrastructure_lifecycle"), [
      certificate?.durable?.terminal_reconciliation_receipt_ref,
      `evidence://c8/journal/${String(certificate?.journal?.outcome_root || "").replace(/^sha256:/u, "")}`,
    ], "Certifies proposal, bounded authority, provider lifecycle, teardown, and terminal financial reconciliation."),
    claim("workload_readiness", status.get("workload_readiness"), [certificate?.provider?.endpoint_ref],
      "Requires provider-native evidence of at least one ready replica; this does not by itself bind an application result."),
    claim("workload_result_binding", false, [],
      "C7/C8 v2 contains no retrieved workload result digest bound into the outcome commitment."),
    claim("logical_policy_mediation", true, [
      certificate?.proposal?.admission_receipt_ref,
      certificate?.proposal?.consumption_receipt_ref,
    ], "Demonstrates daemon admission and one-shot capability consumption, not system-level non-bypassability."),
    claim("workload_bound_isolation_enforced", false, [],
      "No workload-isolation binding and hostile-guest bypass evidence are carried by C7/C8 v2."),
    claim("worker_secret_non_possession_tested", false, [],
      "Credential isolation from model context is not an adversarial worker secret-non-possession test."),
    claim("separate_verifier", status.get("separate_verifier"), [`verification-report://c8/${certificateId}`],
      "A separately invoked verifier passed; this is not an independent reimplementation or third-party verification."),
    claim("independently_reproduced", false, [],
      "The verifier has not yet been independently reimplemented from the published contract."),
    claim("third_party_verified", false, [],
      "No separately accountable external party operated the verifier for this certificate."),
    claim("provider_neutrality", false, [],
      "One Akash lifecycle cannot demonstrate provider-neutral execution."),
    claim("bare_metal_placement", false, [],
      "Provider marketplace execution does not prove certified bare-metal or dedicated-core placement."),
  ];
  const manifest = {
    schema_version: "ioi.components.hypervisor.governed-effect-claim-manifest.v1",
    manifest_ref: `claim-manifest://c8/${certificateId}`,
    subject_ref: certificateRef,
    subject_hash: certificate?.certificate_hash,
    protection_profile: "development_cooperative",
    claims,
    source_basis_refs: [
      {
        ref: `git-commit://ioi/${certificate?.source?.commit}`,
        hash: hash(certificate?.source?.commit),
      },
      {
        ref: `binary://hypervisor-daemon/${String(certificate?.source?.daemon_binary_sha256 || "").replace(/^sha256:/u, "")}`,
        hash: certificate?.source?.daemon_binary_sha256,
      },
    ],
    generated_at: generatedAt,
  };
  manifest.manifest_hash = governedEffectClaimManifestHash(manifest);
  const validation = validateGovernedEffectClaimManifest(manifest, certificate, verification);
  if (!validation.ok) {
    throw new Error(`governed effect claim manifest refused: ${validation.failures.join(",")}`);
  }
  return manifest;
}

export function validateGovernedEffectClaimManifest(manifest, certificate, verification) {
  const failures = [];
  const fail = (code) => failures.push(code);
  if (manifest?.schema_version !== "ioi.components.hypervisor.governed-effect-claim-manifest.v1") fail("schema_version_invalid");
  if (!refValue(manifest?.manifest_ref) || !refValue(manifest?.subject_ref)) fail("manifest_subject_ref_invalid");
  if (!shaValue(manifest?.manifest_hash) || governedEffectClaimManifestHash(manifest) !== manifest.manifest_hash) fail("manifest_hash_mismatch");
  if (!shaValue(manifest?.subject_hash) || manifest.subject_hash !== certificate?.certificate_hash) fail("subject_hash_mismatch");
  if (manifest?.protection_profile !== "development_cooperative") fail("c7_protection_profile_inflated");
  if (!Array.isArray(manifest?.source_basis_refs) || manifest.source_basis_refs.length < 1
    || manifest.source_basis_refs.some((entry) => !refValue(entry?.ref) || !shaValue(entry?.hash))) fail("source_basis_invalid");
  if (!Array.isArray(manifest?.claims)) {
    fail("claims_missing");
    return { ok: false, failures };
  }
  const byId = new Map();
  for (const entry of manifest.claims) {
    if (byId.has(entry?.claim_id)) fail("claim_duplicate");
    byId.set(entry?.claim_id, entry);
    const demonstrated = entry?.status === "demonstrated";
    if (!GOVERNED_EFFECT_CLAIM_IDS.includes(entry?.claim_id)) fail("claim_id_unknown");
    if (!["demonstrated", "not_demonstrated", "indeterminate", "not_applicable"].includes(entry?.status)) fail("claim_status_unknown");
    if (!Array.isArray(entry?.evidence_refs) || entry.evidence_refs.some((evidenceRef) => !refValue(evidenceRef))) fail("claim_evidence_ref_invalid");
    if (demonstrated && entry.evidence_refs.length === 0) fail("demonstrated_claim_without_evidence");
    if (!demonstrated && entry.evidence_refs.length !== 0) fail("nonclaim_carries_evidence");
    if (typeof entry?.limitation_note !== "string" || entry.limitation_note.length === 0) fail("claim_limitation_missing");
  }
  if (byId.size !== GOVERNED_EFFECT_CLAIM_IDS.length
    || GOVERNED_EFFECT_CLAIM_IDS.some((claimId) => !byId.has(claimId))) fail("claim_vocabulary_incomplete");
  for (const [claimId, expected] of expectedC7ClaimStatuses(certificate, verification)) {
    if ((byId.get(claimId)?.status === "demonstrated") !== expected) fail(`claim_inflated:${claimId}`);
  }
  return { ok: failures.length === 0, failures: [...new Set(failures)] };
}
