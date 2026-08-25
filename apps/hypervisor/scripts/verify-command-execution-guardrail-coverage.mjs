#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { emitVerifierCensus } from "./lib/verifier-census.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "..", "..", "..");
const routeDir = path.join(root, "crates/node/src/bin/hypervisor_daemon_routes");
const read = (name) => fs.readFileSync(path.join(routeDir, name), "utf8");
const sources = {
  operability: read("operability_routes.rs"),
  environment: read("environment_routes.rs"),
  supervisor: read("supervisor_routes.rs"),
  provider: read("provider_routes.rs"),
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
  const orderedGuard = (text, start, end, guardNeedle, invocation, code) => {
    const body = segment(text, start, end);
    const guard = body.indexOf(guardNeedle);
    const invoke = body.indexOf(invocation);
    require(guard >= 0 && invoke >= 0 && guard < invoke, code);
  };

  require(
    candidate.operability.includes("pub(crate) fn guardrail_refusal_response("),
    "shared_refusal_owner_missing",
  );
  require(
    !candidate.environment.includes("fn guardrail_refusal_response("),
    "environment_second_refusal_owner_restored",
  );
  orderedGuard(
    candidate.environment,
    "fn run_task(",
    "/// Run a resolution's tasks",
    "guardrail_refusal_response",
    "std::process::Command::new(\"timeout\")",
    "host_resolved_task_bypass",
  );
  orderedGuard(
    candidate.environment,
    "fn typed_service(",
    "/// Typed `HypervisorEnvironmentPort`",
    "guardrail_refusal_response",
    "std::process::Command::new(\"timeout\")",
    "service_healthcheck_bypass",
  );
  orderedGuard(
    candidate.environment,
    "fn run_tasks_in_guest(",
    "/// Export the guest workspace",
    "guardrail_refusal_response",
    "monitor.exec(vm, command)",
    "guest_resolved_task_bypass",
  );
  orderedGuard(
    candidate.environment,
    "pub(crate) async fn handle_workspace_exec(",
    "/// GET /v1/hypervisor/exec-sessions",
    "guardrail_refusal_response",
    "std::process::Command::new(\"bash\")",
    "mounted_exec_bypass",
  );
  orderedGuard(
    candidate.supervisor,
    '"Exec" => {',
    '"CancelExec" =>',
    "supervisor_exec_guardrail_refusal",
    'Command::new("bash")',
    "supervisor_exec_bypass",
  );
  require(
    candidate.supervisor.includes("fn supervisor_exec_guardrail_refusal(") &&
      segment(candidate.supervisor, "fn supervisor_exec_guardrail_refusal(", "/// Resolve `rel`")
        .includes("super::operability_routes::guardrail_refusal_response"),
    "supervisor_shared_owner_not_used",
  );
  require(
    candidate.provider.includes("fn provider_workrun_guardrail_refusal(") &&
      segment(candidate.provider, "fn provider_workrun_guardrail_refusal(", "pub(crate) fn invoke_static_provider_operation(")
        .includes("super::operability_routes::guardrail_refusal_response") &&
      segment(candidate.provider, "fn provider_workrun_guardrail_refusal(", "pub(crate) fn invoke_static_provider_operation(")
        .includes("load_env_guardrail_context"),
    "provider_shared_owner_not_used",
  );
  require(
    candidate.environment.includes("pub(crate) fn load_env_guardrail_context(") &&
      segment(candidate.environment, "pub(crate) fn load_env_guardrail_context(", "fn persist_env(")
        .includes("symlink_metadata"),
    "environment_indeterminacy_collapsed_to_absence",
  );
  require(
    segment(candidate.provider, "pub(crate) fn invoke_static_provider_operation(", "fn provider_write_caller(")
      .includes("provider_workrun_guardrail_refusal(data_dir, provider_id, env_ref, command)"),
    "static_provider_workrun_bypass",
  );
  require(
    candidate.provider.includes("provider_workrun_guardrail_refusal(data_dir, &kind, &env_ref, command)"),
    "account_provider_workrun_bypass",
  );
  return failures;
}

const sourceInvariantNames = [
  "shared_refusal_owner_missing",
  "environment_second_refusal_owner_restored",
  "host_resolved_task_bypass",
  "service_healthcheck_bypass",
  "guest_resolved_task_bypass",
  "mounted_exec_bypass",
  "supervisor_exec_bypass",
  "supervisor_shared_owner_not_used",
  "provider_shared_owner_not_used",
  "environment_indeterminacy_collapsed_to_absence",
  "static_provider_workrun_bypass",
  "account_provider_workrun_bypass",
];
const sourceFailures = analyze(sources);
const results = sourceInvariantNames.map((name) => ({
  name: `source:${name}`,
  pass: !sourceFailures.includes(name),
}));
const failures = sourceFailures.map((code) => ({ code, detail: "source invariant failed" }));

const mutations = [
  ["environment", "fn run_task(", "/// Run a resolution's tasks", "guardrail_refusal_response", "host_resolved_task_bypass"],
  ["environment", "fn typed_service(", "/// Typed `HypervisorEnvironmentPort`", "guardrail_refusal_response", "service_healthcheck_bypass"],
  ["environment", "fn run_tasks_in_guest(", "/// Export the guest workspace", "guardrail_refusal_response", "guest_resolved_task_bypass"],
  ["environment", "pub(crate) async fn handle_workspace_exec(", "/// GET /v1/hypervisor/exec-sessions", "guardrail_refusal_response", "mounted_exec_bypass"],
  ["supervisor", '"Exec" => {', '"CancelExec" =>', "supervisor_exec_guardrail_refusal", "supervisor_exec_bypass"],
];
for (const [file, start, end, guardNeedle, expected] of mutations) {
  const original = sources[file];
  const body = segment(original, start, end);
  const mutatedBody = body.replace(guardNeedle, "guardrail_removed_by_mutation");
  const mutated = { ...sources, [file]: original.replace(body, mutatedBody) };
  const pass = analyze(mutated).includes(expected);
  results.push({ name: `mutation:${expected}`, pass });
  if (!pass) {
    failures.push({ code: "mutation_false_green", detail: `${expected} removal was not detected` });
  }
}
for (const [needle, expected] of [
  ["provider_workrun_guardrail_refusal(data_dir, provider_id, env_ref, command)", "static_provider_workrun_bypass"],
  ["provider_workrun_guardrail_refusal(data_dir, &kind, &env_ref, command)", "account_provider_workrun_bypass"],
]) {
  const mutated = { ...sources, provider: sources.provider.replace(needle, "provider_guard_removed()") };
  const pass = analyze(mutated).includes(expected);
  results.push({ name: `mutation:${expected}`, pass });
  if (!pass) {
    failures.push({ code: "mutation_false_green", detail: `${expected} removal was not detected` });
  }
}
{
  const mutated = {
    ...sources,
    provider: sources.provider.replace("load_env_guardrail_context(data_dir, env_ref)", "load_env(data_dir, env_ref)"),
  };
  const pass = analyze(mutated).includes("provider_shared_owner_not_used");
  results.push({ name: "mutation:provider_environment_indeterminacy", pass });
  if (!pass) {
    failures.push({ code: "mutation_false_green", detail: "provider environment indeterminacy collapse was not detected" });
  }
}

const tests = spawnSync(
  "cargo",
  ["test", "--locked", "-p", "ioi-node", "--bin", "hypervisor-daemon", "command_guardrail_tests", "--no-fail-fast"],
  { cwd: root, encoding: "utf8", maxBuffer: 16 * 1024 * 1024 },
);
results.push({ name: "behavior:command_guardrail_tests_pass", pass: tests.status === 0 });
if (tests.status !== 0) {
  failures.push({ code: "cross_surface_tests_failed", detail: (tests.stderr || tests.stdout).slice(-4000) });
}
for (const name of [
  "supervisor_exec_uses_the_shared_fail_closed_refusal_before_spawn",
  "every_provider_workrun_entry_can_use_the_shared_fail_closed_refusal",
]) {
  const pass = (tests.stdout || "").includes(name);
  results.push({ name: `behavior:${name}`, pass });
  if (!pass) {
    failures.push({ code: "focused_test_not_executed", detail: name });
  }
}
const environmentTest = spawnSync(
  "cargo",
  ["test", "--locked", "-p", "ioi-node", "--bin", "hypervisor-daemon", "resolved_tasks_and_service_healthchecks_refuse_before_host_process_spawn", "--no-fail-fast"],
  { cwd: root, encoding: "utf8", maxBuffer: 16 * 1024 * 1024 },
);
results.push({ name: "behavior:resolved_task_healthcheck_tests_pass", pass: environmentTest.status === 0 });
if (environmentTest.status !== 0) {
  failures.push({ code: "task_healthcheck_test_failed", detail: (environmentTest.stderr || environmentTest.stdout).slice(-4000) });
}
const environmentTestExecuted = (environmentTest.stdout || "").includes("resolved_tasks_and_service_healthchecks_refuse_before_host_process_spawn");
results.push({ name: "behavior:resolved_tasks_and_service_healthchecks_refuse_before_host_process_spawn", pass: environmentTestExecuted });
if (!environmentTestExecuted) {
  failures.push({ code: "focused_test_not_executed", detail: "resolved task / healthcheck refusal" });
}

if (failures.length) {
  console.error(JSON.stringify({ ok: false, schema_version: "ioi.check.command-execution-guardrail-coverage.v1", failures }, null, 2));
  process.exit(1);
}
emitVerifierCensus({ verifierId: "command-execution-guardrails", sourceUrl: import.meta.url, results });
console.log(JSON.stringify({
  ok: true,
  schema_version: "ioi.check.command-execution-guardrail-coverage.v1",
  covered_surfaces: ["workspace_exec", "resolved_task_host", "resolved_task_guest", "service_healthcheck", "supervisor_exec", "static_provider_workrun", "account_provider_workrun"],
  mutation_probes: 8,
  shared_refusal_owner: "operability_routes::guardrail_refusal_response",
}, null, 2));
