#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { sealSelfHash } from "./lib/c8-v3-portable-bundle.mjs";
import { buildRelyingPartyTrustInputs } from "./lib/u1-c8-relying-party-provisioning.mjs";

const repo = path.resolve(import.meta.dirname, "../../..");
const home = process.env.HOME;
if (!home) throw new Error("HOME is required");
const campaignDir = process.env.IOI_U1_CAMPAIGN_EVIDENCE
  || path.join(home, ".ioi/hypervisor/evidence/u1/campaign-o-aes-phl-14d24907/run");
const output = path.resolve(process.argv[2] || path.join(path.dirname(campaignDir), "c8-v3-relying-party"));
const verifier = process.env.IOI_AFT_C8_VERIFIER || path.join(repo, "target/debug/aft-c8-verifier");
const read = (file) => JSON.parse(fs.readFileSync(file, "utf8"));
const write = (name, value) => fs.writeFileSync(path.join(output, name), `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600, flag: "wx" });

if (fs.existsSync(output)) throw new Error(`refusing to overwrite relying-party state: ${output}`);
if (!fs.existsSync(verifier)) throw new Error(`verifier binary missing: ${verifier}`);
const campaign = read(path.join(campaignDir, "u1-campaign-certificate.json"));
const lifecycle = read(path.join(campaignDir, "c7-c8-certificate.json"));
const source = {
  schema_version: "ioi.foundations.source-basis.v1",
  commit: campaign.authority.source_commit,
  image_digest: campaign.authority.image_digest,
};
const { policy, profile } = buildRelyingPartyTrustInputs({ verifierPath: verifier, sourceBasis: source });
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
