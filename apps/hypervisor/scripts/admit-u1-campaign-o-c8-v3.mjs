#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { assemblePortableBundle, contentHash } from "./lib/c8-v3-portable-bundle.mjs";
import {
  buildRelyingPartyTrustInputs,
  differencesOutsideBuildLineage,
} from "./lib/u1-c8-relying-party-provisioning.mjs";
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
const acceptedAt = process.env.IOI_C8_ACCEPTED_AT || new Date().toISOString();
const expectedRevision = Number(process.env.IOI_C8_EXPECTED_REGISTRY_REVISION ?? "0");
if (!Number.isSafeInteger(expectedRevision) || expectedRevision < 0) {
  throw new Error("IOI_C8_EXPECTED_REGISTRY_REVISION must be a non-negative integer");
}
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
  const retainedPolicy = read(policyPath);
  const retainedProfile = read(profilePath);
  const registryBefore = read(registryPath);
  const campaign = read(path.join(campaignDir, "u1-campaign-certificate.json"));
  const sourceBasis = {
    schema_version: "ioi.foundations.source-basis.v1",
    commit: campaign.authority.source_commit,
    image_digest: campaign.authority.image_digest,
  };
  const { policy, profile, verifierBuildHash } = buildRelyingPartyTrustInputs({
    verifierPath: verifier,
    sourceBasis,
  });

  mustEqual(retainedPolicy.verifier_profile_hash, contentHash(retainedProfile), "retained policy verifier profile");
  for (const [kind, current, retained] of [
    ["policy", policy, retainedPolicy],
    ["profile", profile, retainedProfile],
  ]) {
    const drift = differencesOutsideBuildLineage(current, retained, kind);
    if (drift.length > 0) {
      throw new Error(`re-derived relying-party ${kind} drifted outside the build lineage: ${drift.join(", ")}`);
    }
  }

  const inputs = buildCampaignBundleInputs({ campaignDir, dataDir, policy, generatedAt: acceptedAt, writeTemp });
  const derivedPolicyPath = writeTemp("re-derived-policy.json", policy);
  const derivedProfilePath = writeTemp("re-derived-verifier-profile.json", profile);

  mustEqual(profile.verifier_build_hash, hashBytes(fs.readFileSync(verifier)), "re-derived verifier build");
  mustEqual(profile.verifier_build_hash, verifierBuildHash, "re-derived verifier build result");
  mustEqual(policy.verifier_profile_hash, contentHash(profile), "re-derived verifier profile");
  mustEqual(policy.trust_roots[0]?.ref, inputs.refs.source, "re-derived source trust root ref");
  mustEqual(policy.trust_roots[0]?.hash, contentHash(inputs.sourceBasis), "re-derived source trust root hash");
  mustEqual(registryBefore.revision, expectedRevision, "pre-provisioned registry revision");

  const draftPath = writeTemp("certificate-draft.json", inputs.draft);
  const bundleDir = path.join(output, "portable-bundle");
  fs.mkdirSync(output, { recursive: false, mode: 0o700 });
  fs.writeFileSync(
    path.join(output, "registry-before.json"),
    `${JSON.stringify(registryBefore, null, 2)}\n`,
    { mode: 0o600, flag: "wx" },
  );
  fs.copyFileSync(policyPath, path.join(output, "retained-policy.json"), fs.constants.COPYFILE_EXCL);
  fs.copyFileSync(profilePath, path.join(output, "retained-verifier-profile.json"), fs.constants.COPYFILE_EXCL);
  assemblePortableBundle({
    bundle_ref: inputs.bundleRef, created_at: acceptedAt, certificate_draft_path: draftPath,
    certificate_file: "certificate.json", objects: inputs.objects,
    trust_inputs: [
      { ref: policy.policy_ref, schema_ref: "schema://ioi/foundations/relying-party-acceptance-policy/v1", file: "policy.json", path: derivedPolicyPath },
      { ref: profile.profile_ref, schema_ref: "schema://ioi/foundations/verifier-independence-profile/v1", file: "verifier-profile.json", path: derivedProfilePath },
    ],
  }, bundleDir);
  const rowPath = path.join(output, "accepted-row.json");
  const receiptPath = path.join(output, "acceptance-receipt.json");
  const accepted = spawnSync(verifier, ["accept", "--bundle", bundleDir, "--policy", path.join(bundleDir, "policy.json"), "--registry", registryPath, "--row-output", rowPath, "--receipt", receiptPath, "--expected-revision", String(expectedRevision), "--now", acceptedAt], { cwd: repo, encoding: "utf8" });
  if (accepted.status !== 0) throw new Error(`registry admission failed: ${accepted.stderr || accepted.stdout}`);
  const after = read(registryPath);
  const receipt = read(receiptPath);
  if (after.revision !== expectedRevision + 1
      || after.entries.length !== registryBefore.entries.length + 1
      || receipt.decision !== "accepted"
      || receipt.mutation_applied !== true) {
    throw new Error("registry did not perform exactly one accepted state transition");
  }
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
    verifier_rebuilt_since_provisioning: retainedProfile.verifier_build_hash !== profile.verifier_build_hash,
    retained_verifier_build_hash: retainedProfile.verifier_build_hash,
  };
  fs.writeFileSync(path.join(output, "admission-summary.json"), `${JSON.stringify(summary, null, 2)}\n`, { mode: 0o600, flag: "wx" });
  console.log(JSON.stringify({ ok: true, output, ...summary }));
} catch (error) {
  if (fs.existsSync(output)) fs.writeFileSync(path.join(output, "FAILED.txt"), `${error.stack || error}\n`, { mode: 0o600 });
  throw error;
} finally {
  fs.rmSync(temp, { recursive: true, force: true });
}
