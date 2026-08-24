#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";

const repo = path.resolve(import.meta.dirname, "../../..");
const bundleDir = path.resolve(process.argv[2] || "");
const now = process.argv[3] || "2026-08-23T23:45:00Z";
if (!bundleDir || !fs.existsSync(path.join(bundleDir, "bundle.json"))) throw new Error("portable bundle directory is required");
const checks = [
  ["isolation-requirements.json", "hypervisor-workload-isolation-requirements.v1.schema.json"],
  ["isolation.json", "hypervisor-workload-isolation-binding.v1.schema.json"],
  ["envelope.json", "standing-authority-envelope.v1.schema.json"],
  ["auth-factor.json", "auth-factor-receipt.v1.schema.json"],
  ["trajectory-before.json", "authority-trajectory-state.v1.schema.json"],
  ["trajectory-after.json", "authority-trajectory-state.v1.schema.json"],
  ["trajectory-decision.json", "trajectory-admission-decision.v1.schema.json"],
  ["claims.json", "governed-effect-claim-manifest.v1.schema.json"],
  ["certificate.json", "c8-certificate.v3.schema.json"],
  ["bundle.json", "c8-portable-evidence-bundle.v1.schema.json"],
  ["policy.json", "relying-party-acceptance-policy.v1.schema.json"],
  ["verifier-profile.json", "verifier-independence-profile.v1.schema.json"],
  ["result.json", "aft-u1-campaign-result.v1.schema.json"],
];
for (const [file, schemaName] of checks) {
  const ajv = new Ajv2020({ allErrors: true, strict: false });
  addFormats(ajv);
  const schema = JSON.parse(fs.readFileSync(path.join(repo, "docs/architecture/_meta/schemas", schemaName), "utf8"));
  const value = JSON.parse(fs.readFileSync(path.join(bundleDir, file), "utf8"));
  const validate = ajv.compile(schema);
  if (!validate(value)) throw new Error(`${file} violates ${schema.$id}: ${ajv.errorsText(validate.errors)}`);
}
const certificate = JSON.parse(fs.readFileSync(path.join(bundleDir, "certificate.json"), "utf8"));
const predecessor = JSON.parse(fs.readFileSync(path.join(bundleDir, "predecessor.json"), "utf8"));
if (predecessor.schema_version !== certificate.predecessor_certificate_schema_version
  || predecessor.certificate_hash !== certificate.predecessor_certificate_hash
  || predecessor.ok !== true) throw new Error("portable bundle does not carry the complete exact predecessor certificate");
const verifier = process.env.IOI_AFT_C8_VERIFIER || path.join(repo, "target/debug/aft-c8-verifier");
const verified = spawnSync(verifier, ["verify", "--bundle", bundleDir, "--policy", path.join(bundleDir, "policy.json"), "--now", now], { cwd: repo, encoding: "utf8" });
if (verified.status !== 0) throw new Error(verified.stderr || verified.stdout || "separate verifier refused bundle");
console.log(JSON.stringify({ ok: true, canonical_schema_checks: checks.length, predecessor_hash: predecessor.certificate_hash, certificate_hash: certificate.certificate_hash }));
