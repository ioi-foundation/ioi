#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { assemblePortableBundle, contentHash } from "./lib/c8-v3-portable-bundle.mjs";
import { buildCampaignBundleInputs } from "./lib/u1-campaign-c8-v3-bundle.mjs";

const repo = path.resolve(import.meta.dirname, "../../..");
const home = process.env.HOME;
if (!home) throw new Error("HOME is required");
const campaignDir = process.env.IOI_U1_CAMPAIGN_EVIDENCE
  || path.join(home, ".ioi/hypervisor/evidence/u1/campaign-o-aes-phl-14d24907/run");
const dataDir = process.env.IOI_HYPERVISOR_DATA_DIR || path.join(home, ".ioi/hypervisor/data");
const output = path.resolve(process.argv[2] || path.join(path.dirname(campaignDir), "c8-v3-registry-admission"));
const relyingPartyDir = process.env.IOI_C8_RELYING_PARTY_DIR;
if (!relyingPartyDir) throw new Error("IOI_C8_RELYING_PARTY_DIR is required; provision relying-party policy and registry separately");
const verifier = process.env.IOI_AFT_C8_VERIFIER || path.join(repo, "target/debug/aft-c8-verifier");
const acceptedAt = "2026-08-23T23:45:00Z";
const temp = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-u1-c8-v3-real-"));
const read = (file) => JSON.parse(fs.readFileSync(file, "utf8"));
const writeTemp = (name, value) => {
  const target = path.join(temp, name);
  fs.writeFileSync(target, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600, flag: "wx" });
  return target;
};
const hashBytes = (bytes) => `sha256:${crypto.createHash("sha256").update(bytes).digest("hex")}`;
const mustEqual = (actual, expected, label) => {
  if (actual !== expected) throw new Error(`${label}: expected ${expected}, observed ${actual}`);
};

try {
  if (fs.existsSync(output)) throw new Error(`refusing to overwrite existing admission: ${output}`);
  if (!fs.existsSync(verifier)) throw new Error(`verifier binary missing: ${verifier}`);

  const policyPath = path.join(relyingPartyDir, "policy.json");
  const profilePath = path.join(relyingPartyDir, "verifier-profile.json");
  const registryPath = path.join(relyingPartyDir, "registry.json");
  const policy = read(policyPath);
  const profile = read(profilePath);
  const registryBefore = read(registryPath);

  const inputs = buildCampaignBundleInputs({ campaignDir, dataDir, policy, generatedAt: acceptedAt, writeTemp });

  mustEqual(profile.verifier_build_hash, hashBytes(fs.readFileSync(verifier)), "pre-provisioned verifier build");
  mustEqual(policy.verifier_profile_hash, contentHash(profile), "pre-provisioned verifier profile");
  mustEqual(policy.trust_roots[0]?.ref, inputs.refs.source, "pre-provisioned source trust root ref");
  mustEqual(policy.trust_roots[0]?.hash, contentHash(inputs.sourceBasis), "pre-provisioned source trust root hash");
  mustEqual(registryBefore.revision, 0, "pre-provisioned registry revision");

  const draftPath = writeTemp("certificate-draft.json", inputs.draft);
  const bundleDir = path.join(output, "portable-bundle");
  fs.mkdirSync(output, { recursive: false, mode: 0o700 });
  assemblePortableBundle({
    bundle_ref: inputs.bundleRef, created_at: acceptedAt, certificate_draft_path: draftPath,
    certificate_file: "certificate.json", objects: inputs.objects,
    trust_inputs: [
      { ref: policy.policy_ref, schema_ref: "schema://ioi/foundations/relying-party-acceptance-policy/v1", file: "policy.json", path: policyPath },
      { ref: profile.profile_ref, schema_ref: "schema://ioi/foundations/verifier-independence-profile/v1", file: "verifier-profile.json", path: profilePath },
    ],
  }, bundleDir);
  const rowPath = path.join(output, "accepted-row.json");
  const receiptPath = path.join(output, "acceptance-receipt.json");
  const accepted = spawnSync(verifier, ["accept", "--bundle", bundleDir, "--policy", path.join(bundleDir, "policy.json"), "--registry", registryPath, "--row-output", rowPath, "--receipt", receiptPath, "--expected-revision", "0", "--now", acceptedAt], { cwd: repo, encoding: "utf8" });
  if (accepted.status !== 0) throw new Error(`registry admission failed: ${accepted.stderr || accepted.stdout}`);
  const after = read(registryPath);
  const receipt = read(receiptPath);
  if (after.revision !== 1 || after.entries.length !== 1 || receipt.decision !== "accepted" || receipt.mutation_applied !== true) throw new Error("registry did not perform exactly one accepted state transition");
  fs.copyFileSync(registryPath, path.join(output, "registry.json"), fs.constants.COPYFILE_EXCL);
  fs.copyFileSync(path.join(relyingPartyDir, "provisioning.json"), path.join(output, "relying-party-provisioning.json"), fs.constants.COPYFILE_EXCL);
  const summary = {
    schema_version: "ioi.aft.c8-v3-offline-registry-admission-summary.v1", campaign_id: inputs.campaignId,
    bundle_ref: read(path.join(bundleDir, "bundle.json")).bundle_ref, certificate_ref: receipt.certificate_ref,
    certificate_hash: receipt.certificate_hash, policy_ref: receipt.policy_ref, policy_hash: receipt.policy_hash,
    verifier_identity_ref: receipt.verifier_identity_ref, verifier_build_hash: receipt.verifier_build_hash,
    decision: receipt.decision, mutation_applied: receipt.mutation_applied, accepted_revision: receipt.accepted_revision,
    accepted_object_refs: receipt.accepted_object_refs, registry_state_before_hash: receipt.target_state_before_hash,
    registry_state_after_hash: receipt.target_state_after_hash, result_verdict: inputs.result.verdict,
    hard_secret_non_possession_scope: inputs.isolationProbe.claim_boundary,
  };
  fs.writeFileSync(path.join(output, "admission-summary.json"), `${JSON.stringify(summary, null, 2)}\n`, { mode: 0o600, flag: "wx" });
  console.log(JSON.stringify({ ok: true, output, ...summary }));
} catch (error) {
  if (fs.existsSync(output)) fs.writeFileSync(path.join(output, "FAILED.txt"), `${error.stack || error}\n`, { mode: 0o600 });
  throw error;
} finally {
  fs.rmSync(temp, { recursive: true, force: true });
}
