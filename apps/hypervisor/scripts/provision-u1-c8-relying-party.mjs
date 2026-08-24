#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { contentHash, sealSelfHash } from "./lib/c8-v3-portable-bundle.mjs";

const repo = path.resolve(import.meta.dirname, "../../..");
const home = process.env.HOME;
if (!home) throw new Error("HOME is required");
const campaignDir = process.env.IOI_U1_CAMPAIGN_EVIDENCE
  || path.join(home, ".ioi/hypervisor/evidence/u1/campaign-o-aes-phl-14d24907/run");
const output = path.resolve(process.argv[2] || path.join(path.dirname(campaignDir), "c8-v3-relying-party"));
const verifier = process.env.IOI_AFT_C8_VERIFIER || path.join(repo, "target/debug/aft-c8-verifier");
const read = (file) => JSON.parse(fs.readFileSync(file, "utf8"));
const write = (name, value) => fs.writeFileSync(path.join(output, name), `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600, flag: "wx" });
const hashBytes = (bytes) => `sha256:${crypto.createHash("sha256").update(bytes).digest("hex")}`;

if (fs.existsSync(output)) throw new Error(`refusing to overwrite relying-party state: ${output}`);
if (!fs.existsSync(verifier)) throw new Error(`verifier binary missing: ${verifier}`);
const campaign = read(path.join(campaignDir, "u1-campaign-certificate.json"));
const lifecycle = read(path.join(campaignDir, "c7-c8-certificate.json"));
const source = {
  schema_version: "ioi.foundations.source-basis.v1",
  commit: campaign.authority.source_commit,
  image_digest: campaign.authority.image_digest,
};
const profile = sealSelfHash({
  schema_version: "ioi.foundations.verifier-independence-profile.v1",
  profile_ref: "verifier-profile://aft/c8-v3/real-u1-canon",
  verifier_identity_ref: "verifier://ioi/aft-c8-verifier",
  verifier_build_hash: hashBytes(fs.readFileSync(verifier)),
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
  trust_roots: [{ ref: `source://ioi/aft/${campaign.authority.source_commit}`, hash: contentHash(source) }],
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
const registry = sealSelfHash({
  schema_version: "ioi.aft.measured-results-registry.v1",
  registry_ref: "registry://aft/measured-results",
  revision: 0,
  previous_state_hash: null,
  entries: [],
});
fs.mkdirSync(output, { mode: 0o700 });
write("policy.json", policy);
write("verifier-profile.json", profile);
write("registry.json", registry);
write("provisioning.json", {
  schema_version: "ioi.aft.c8-v3-relying-party-provisioning.v1",
  owner_ref: "relying-party://aft/measured-results-registry",
  campaign_id: campaign.authority.campaign_id,
  predecessor_certificate_hash: lifecycle.certificate_hash,
  policy_hash: policy.policy_hash,
  verifier_profile_hash: profile.profile_hash,
  registry_state_hash: registry.state_hash,
  provisioned_at: "2026-08-23T23:44:00Z",
});
console.log(JSON.stringify({ ok: true, output, policy_hash: policy.policy_hash, verifier_profile_hash: profile.profile_hash, registry_state_hash: registry.state_hash }));
