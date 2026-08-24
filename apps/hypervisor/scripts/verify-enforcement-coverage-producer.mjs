#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "..", "..", "..");
const routeDir = path.join(root, "crates/node/src/bin/hypervisor_daemon_routes");
const read = (file) => fs.readFileSync(path.join(root, file), "utf8");
const sources = {
  producer: read("crates/node/src/bin/hypervisor_daemon_routes/enforcement_coverage_routes.rs"),
  gateway: read("crates/node/src/bin/hypervisor_daemon_routes/authority_gateway_routes.rs"),
  node: read("crates/node/src/bin/hypervisor_daemon_routes/hypervisoros_node_routes.rs"),
};

function segment(text, start, end) {
  const from = text.indexOf(start);
  if (from < 0) return "";
  const to = text.indexOf(end, from + start.length);
  return text.slice(from, to < 0 ? text.length : to);
}

function analyze(candidate) {
  const failures = [];
  const require = (condition, code) => { if (!condition) failures.push(code); };
  const producer = candidate.producer;
  const create = segment(candidate.gateway, "pub(crate) async fn handle_action_request_create(", "pub(crate) async fn handle_action_request_execute(");
  const execute = segment(candidate.gateway, "pub(crate) async fn handle_action_request_execute(", "pub(crate) async fn handle_action_request_get(");

  require(
    producer.includes("admit_owner_scoped_write(") &&
      producer.includes('const OWNER_NAMESPACE: &str = "hypervisor-enforcement-coverage"') &&
      producer.includes("list_event_stream_tails(data_dir, OWNER_NAMESPACE)"),
    "agentgres_lifecycle_missing",
  );
  require(
    !producer.includes("durable_fs") && !producer.includes("atomic_write_json"),
    "second_durable_plane_restored",
  );
  require(
    segment(producer, "pub(crate) fn produce_gateway_profile(", "#[allow(clippy::too_many_arguments)]")
      .includes("None,"),
    "profile_registration_overclaims",
  );
  require(
    segment(producer, "pub(crate) fn produce_gateway_action(", "fn resolve_gateway_profile_with_posture(")
      .includes("Some((decision_receipt_ref, action_admission_receipt_ref))"),
    "observed_action_proof_missing",
  );
  require(
    create.includes("produce_observed_action_coverage(") &&
      create.includes("false,") &&
      execute.includes("true,"),
    "create_execute_posture_split_missing",
  );
  require(
    producer.includes("resolve_gateway_classification(") &&
      producer.includes("resolve_gateway_profile(") &&
      producer.includes("EnforcementCoverageEvidenceRequirement::VerificationAndReceipt"),
    "lifecycle_resolver_bypass",
  );
  require(
    !candidate.gateway.includes('read_record_dir(&state.data_dir, "hypervisoros-node-evidence")') &&
      !candidate.node.includes('read_record_dir(&state.data_dir, "hypervisoros-node-evidence")'),
    "loose_evidence_truth_restored",
  );
  return failures;
}

const failures = analyze(sources).map((code) => ({ code, detail: "source invariant failed" }));
const mutations = [
  ["producer", "admit_owner_scoped_write(", "agentgres_lifecycle_missing"],
  ["producer", "list_event_stream_tails(data_dir, OWNER_NAMESPACE)", "agentgres_lifecycle_missing"],
  ["producer", "profile_admission_receipt_ref,\n        Some((decision_receipt_ref, action_admission_receipt_ref))", "observed_action_proof_missing"],
  ["gateway", "produce_observed_action_coverage(", "create_execute_posture_split_missing"],
  ["producer", "EnforcementCoverageEvidenceRequirement::VerificationAndReceipt", "lifecycle_resolver_bypass"],
];
for (const [file, needle, expected] of mutations) {
  const mutated = { ...sources, [file]: sources[file].replaceAll(needle, "removed_by_mutation") };
  if (!analyze(mutated).includes(expected)) {
    failures.push({ code: "mutation_false_green", detail: `${expected}: ${needle}` });
  }
}

for (const [filter, expected] of [
  ["enforcement_coverage_routes::tests", "observed_action_supersedes_the_gap_and_rebuilds_from_agentgres"],
  ["authority_gateway_routes::tests", "exact_current_profile_surface_and_coverage_admit"],
]) {
  const test = spawnSync(
    "cargo",
    ["test", "--locked", "-p", "ioi-node", "--bin", "hypervisor-daemon", filter, "--no-fail-fast"],
    { cwd: root, encoding: "utf8", maxBuffer: 16 * 1024 * 1024 },
  );
  if (test.status !== 0) {
    failures.push({ code: "behavioral_tests_failed", detail: (test.stderr || test.stdout).slice(-4000) });
  } else if (!(test.stdout || "").includes(expected)) {
    failures.push({ code: "focused_test_not_executed", detail: expected });
  }
}

if (failures.length) {
  console.error(JSON.stringify({ ok: false, schema_version: "ioi.check.enforcement-coverage-producer.v1", failures }, null, 2));
  process.exit(1);
}
console.log(JSON.stringify({
  ok: true,
  schema_version: "ioi.check.enforcement-coverage-producer.v1",
  durable_owner: "Agentgres owner-scoped admission history",
  producer_stages: ["profile_uncovered_baseline", "observed_action_positive_successor"],
  mutation_probes: mutations.length,
}, null, 2));
