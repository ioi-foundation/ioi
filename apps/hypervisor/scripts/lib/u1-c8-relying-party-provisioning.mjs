import crypto from "node:crypto";
import fs from "node:fs";
import { contentHash, sealSelfHash } from "./c8-v3-portable-bundle.mjs";

// The relying party's trust inputs. The verifier profile pins the exact verifier
// build, and the verifier refuses a profile that does not name its own
// executable — so rebuilding the verifier necessarily re-derives these. Only the
// build lineage may differ between two provisionings of the same policy.

export const BUILD_LINEAGE_FIELDS = {
  profile: ["verifier_build_hash", "profile_hash"],
  policy: ["verifier_profile_hash", "policy_hash"],
};

export function buildRelyingPartyTrustInputs({ verifierPath, sourceBasis }) {
  const verifierBuildHash = `sha256:${crypto.createHash("sha256").update(fs.readFileSync(verifierPath)).digest("hex")}`;
  const profile = sealSelfHash({
    schema_version: "ioi.foundations.verifier-independence-profile.v1",
    profile_ref: "verifier-profile://aft/c8-v3/real-u1-canon",
    verifier_identity_ref: "verifier://ioi/aft-c8-verifier",
    verifier_build_hash: verifierBuildHash,
    contract_schema_refs: ["schema://ioi/components/hypervisor/c8-certificate/v3", "schema://ioi/aft/u1-campaign-result/v1"],
    separate_binary: true,
    separate_codegen: true,
    separate_transport: true,
    separate_authoring_party: false,
    accountable_authoring_party_ref: "principal://ioi/aft-verifier-maintainers",
    evidence_refs: ["evidence://verifier/separate-rust-binary", "evidence://verifier/manual-types", "evidence://verifier/portable-filesystem-transport"],
  });
  const policy = sealSelfHash({
    schema_version: "ioi.foundations.relying-party-acceptance-policy.v1",
    policy_ref: "acceptance-policy://aft/measured-results/variance-caveated-canon-v1",
    audience_ref: "relying-party://aft/measured-results-registry",
    accepted_certificate_schema_refs: ["schema://ioi/components/hypervisor/c8-certificate/v3"],
    accepted_result_schema_refs: ["schema://ioi/aft/u1-campaign-result/v1"],
    trust_roots: [{ ref: `source://ioi/aft/${sourceBasis.commit}`, hash: contentHash(sourceBasis) }],
    maximum_certificate_age_seconds: 604800,
    revocation_check_required: false,
    required_claim_ids: ["governed_infrastructure_lifecycle", "workload_readiness", "workload_result_binding", "logical_policy_mediation", "workload_bound_isolation_enforced", "worker_secret_non_possession_tested", "separate_verifier"],
    tolerated_nonclaim_ids: ["independently_reproduced", "third_party_verified", "provider_neutrality", "bare_metal_placement"],
    accepted_environment_classes: ["measured_container"],
    accepted_honesty_classes: ["same_provider_container_unknown_host"],
    accepted_result_verdicts: ["variance_caveated"],
    verifier_profile_ref: profile.profile_ref,
    verifier_profile_hash: profile.profile_hash,
    target_transition: { target_registry_ref: "registry://aft/measured-results", mutation_kind: "aft_measured_result_promote", target_schema_ref: "schema://ioi/aft/measured-result-row/v1" },
    valid_from: "2026-08-23T00:00:00Z",
    valid_until: "2026-08-30T23:59:59Z",
  });
  return { policy, profile, verifierBuildHash };
}

// Two provisionings of one policy are the same relying party when they differ
// only in the build lineage. Anything else is a policy change, not a rebuild.
export function differencesOutsideBuildLineage(current, retained, kind) {
  const ignored = new Set(BUILD_LINEAGE_FIELDS[kind]);
  const keys = new Set([...Object.keys(current), ...Object.keys(retained)]);
  return [...keys]
    .filter((key) => !ignored.has(key))
    .filter((key) => JSON.stringify(current[key]) !== JSON.stringify(retained[key]));
}
