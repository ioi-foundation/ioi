#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "..", "..", "..");
const providerPath = path.join(root, "crates/node/src/bin/hypervisor_daemon_routes/provider_routes.rs");
const daemonPath = path.join(root, "crates/node/src/bin/hypervisor-daemon.rs");
const source = fs.readFileSync(providerPath, "utf8");
const daemon = fs.readFileSync(daemonPath, "utf8");
const failures = [];
const assert = (condition, code, detail) => { if (!condition) failures.push({ code, detail }); };

function analyze(text, routerText) {
  const findings = [];
  const requireText = (needle, code) => { if (!text.includes(needle)) findings.push(code); };
  const forbidText = (needle, code) => { if (text.includes(needle)) findings.push(code); };
  requireText("provider_operation_inline_proposal_forbidden", "inline_assertion_not_refused");
  requireText("provider-operation-proposal://", "opaque_proposal_ref_absent");
  requireText("provider_operation_proposal.admitted", "durable_admission_absent");
  requireText("provider_operation_proposal.consumed", "durable_consumption_absent");
  requireText("principal_ref", "principal_binding_absent");
  requireText("session_binding", "session_binding_absent");
  requireText("proposal_idempotency_key", "proposal_idempotency_namespace_absent");
  requireText("operation_idempotency_key", "approved_operation_binding_absent");
  requireText("request_hash", "request_binding_absent");
  requireText("resource_refs", "resource_binding_absent");
  requireText("expires_at_unix", "expiry_binding_absent");
  requireText("one_time_nonce", "one_time_nonce_absent");
  requireText("Some(&admitted.head)", "atomic_compare_and_swap_absent");
  requireText("provider_operation_proposal_replayed", "replay_refusal_absent");
  requireText("proposal_admission_receipt_ref", "admission_receipt_absent");
  requireText("proposal_consumption_receipt_ref", "consumption_receipt_absent");
  forbidText("RuntimeHypervisorApprovedOperationAdmissionCore", "caller_asserted_literal_admission_restored");
  if (!routerText.includes('"/v1/hypervisor/provider-operation-proposals"')) findings.push("issuance_route_absent");
  return findings;
}

for (const finding of analyze(source, daemon)) failures.push({ code: finding, detail: "source invariant failed" });

// Mutation drill: restoring the old literal-only admission must make this verifier red.
const mutated = `${source}\n// mutation probe\nRuntimeHypervisorApprovedOperationAdmissionCore`;
assert(
  analyze(mutated, daemon).includes("caller_asserted_literal_admission_restored"),
  "mutation_probe_false_green",
  "the verifier did not detect restoration of the caller-asserted literal admission path",
);

const tests = spawnSync(
  "cargo",
  ["test", "-p", "ioi-node", "--bin", "hypervisor-daemon", "provider_routes::containment_tests", "--no-fail-fast"],
  { cwd: root, encoding: "utf8", maxBuffer: 16 * 1024 * 1024 },
);
assert(tests.status === 0, "provider_provenance_tests_failed", (tests.stderr || tests.stdout).slice(-4000));
assert(
  (tests.stdout || "").includes("daemon_issued_proposal_consumes_once_and_replay_refuses"),
  "one_time_positive_control_not_executed",
  "the exact one-time consume/replay test did not run",
);
assert(
  (tests.stdout || "").includes("inline_literal_tamper_and_session_substitution_all_refuse"),
  "unsafe_mutation_test_not_executed",
  "the inline/tamper/session refusal test did not run",
);
assert(
  (tests.stdout || "").includes("fresh_proposal_admission_does_not_change_the_approved_operation_key"),
  "proposal_operation_idempotency_separation_test_not_executed",
  "the fresh proposal admission / stable approved operation key test did not run",
);

if (failures.length) {
  console.error(JSON.stringify({ ok: false, schema_version: "ioi.check.provider-proposal-provenance.v1", failures }, null, 2));
  process.exit(1);
}
console.log(JSON.stringify({
  ok: true,
  schema_version: "ioi.check.provider-proposal-provenance.v1",
  assertions: 22,
  mutation_probe: "old literal-only admission detected",
  tests: "daemon-issued admission/consume, replay, inline, tamper, session substitution and proposal/operation idempotency separation",
}, null, 2));
