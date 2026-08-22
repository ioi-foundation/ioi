#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { sealU1Certificate, validateU1Certificate } from "./lib/u1-campaign-certificate.mjs";
import { validU1Fixture } from "./lib/u1-campaign-certificate.test-fixture.mjs";

const arg = (name) => {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : null;
};

export function mutationTest(base) {
  const cases = [
    ["u1_campaign_not_successful", (c) => { c.ok = false; }],
    ["u1_lifecycle_certificate_unverified", (c) => { c.lifecycle.verification_ok = false; }],
    ["u1_lifecycle_source_not_clean", (c) => { c.lifecycle.source_dirty_state = "dirty"; }],
    ["u1_lifecycle_source_invalid", (c) => { c.lifecycle.source_commit = "short"; }],
    ["u1_authority_hash_invalid", (c) => { c.authority.request_hash = "bad"; }],
    ["u1_result_tls_pin_invalid", (c) => { c.authority.result_tls_server_certificate_sha256 = "sha256:bad"; }],
    ["u1_workload_identity_invalid", (c) => { c.authority.image_digest = "sha256:bad"; }],
    ["u1_protocol_contract_invalid", (c) => { c.authority.measured_passes = 4; }],
    ["u1_provider_pin_invalid", (c) => { c.authority.provider_selector.provider_address = "akash1other"; }],
    ["u1_spend_posture_invalid", (c) => { c.authority.auto_topup = true; }],
    ["u1_environment_mismatch", (c) => { c.measurement.environment.source_commit = "c".repeat(40); }],
    ["u1_status_not_complete", (c) => { c.measurement.status.state = "measuring"; }],
    ["u1_aggregate_identity_mismatch", (c) => { c.measurement.aggregate.row_count_per_pass = 9; }],
    ["u1_threshold_policy_changed", (c) => { c.measurement.aggregate.threshold_policy.commit_max_ms = 0.5; }],
    ["u1_duplicate_summary_row", (c) => { c.measurement.aggregate.summaries[1] = structuredClone(c.measurement.aggregate.summaries[0]); }],
    ["u1_metric_summary_invalid", (c) => { c.measurement.aggregate.summaries[0].metrics.commit_p99_ms.count = 4; }],
    ["u1_row_verdict_mismatch", (c) => { c.measurement.aggregate.summaries[0].within_threshold = false; }],
    ["u1_matrix_incomplete", (c) => { c.measurement.aggregate.summaries.pop(); }],
    ["u1_campaign_verdict_mismatch", (c) => { c.measurement.aggregate.verdict = "variance_caveated"; }],
    ["u1_manifest_identity_mismatch", (c) => { c.measurement.manifest.campaign_id = "stale"; }],
    ["u1_manifest_binding_mismatch", (c) => { c.measurement.manifest.artifacts[0].sha256 = `sha256:${"0".repeat(64)}`; }],
    ["u1_response_hash_missing", (c) => { c.measurement.response_hashes.status.sha256 = null; }],
    ["u1_response_body_mismatch", (c) => { c.measurement.aggregate.summaries[0].metrics.commit_p50_ms.median = 100.5; }],
    ["u1_provider_lifecycle_mismatch", (c) => { c.provider.lease_state = "open"; }],
    ["u1_settlement_not_terminal", (c) => { c.settlement.open_exposure_count = 1; }],
    ["u1_unsupported_bare_metal_claim", (c) => { c.claims.bare_metal_claimed = true; }],
    ["u1_claim_scope_invalid", (c) => { c.claims.formal_theorem_claimed = true; }],
    ["u1_nonclaims_missing", (c) => { c.nonclaims = []; }],
    ["u1_secret_bearing_certificate", (c) => { c.session_token = "ioi_sess_forbidden"; }],
  ];
  const failures = [];
  for (const [expected, mutate] of cases) {
    const certificate = structuredClone(base);
    mutate(certificate);
    certificate.certificate_hash = sealU1Certificate(certificate).certificate_hash;
    const result = validateU1Certificate(certificate);
    if (result.ok || !result.failures.some((failure) => failure.code === expected)) {
      failures.push({ code: "mutation_false_green", mutation: expected, observed: result.failures });
    }
  }
  return { ok: failures.length === 0, mutation_count: cases.length, failures };
}

if (process.argv.includes("--self-test")) {
  const fixture = validU1Fixture();
  const positive = validateU1Certificate(fixture);
  const mutations = mutationTest(fixture);
  const result = { ok: positive.ok && mutations.ok, positive, mutations };
  console.log(JSON.stringify({ schema_version: "ioi.check.u1-aft-campaign.self-test.v1", ...result }, null, 2));
  process.exit(result.ok ? 0 : 1);
}

const certificateArg = arg("--certificate");
if (!certificateArg) throw new Error("usage: --certificate <u1-campaign-certificate.json> [--mutation-test] | --self-test");
const certificatePath = path.resolve(certificateArg);
const certificate = JSON.parse(fs.readFileSync(certificatePath, "utf8"));
const validation = validateU1Certificate(certificate);
const mutations = process.argv.includes("--mutation-test") ? mutationTest(certificate) : null;
const result = { ok: validation.ok && (mutations?.ok ?? true), failures: [...validation.failures, ...(mutations?.failures || [])] };
console.log(JSON.stringify({ schema_version: "ioi.check.u1-aft-campaign.v1", certificate: certificatePath, ...result, ...(mutations ? { mutations } : {}) }, null, 2));
process.exit(result.ok ? 0 : 1);
