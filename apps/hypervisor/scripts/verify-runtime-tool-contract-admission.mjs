#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "..", "..", "..");
const read = (file) => fs.readFileSync(path.join(root, file), "utf8");
const sources = {
  action: read("crates/services/src/agentic/runtime/service/handler/execution/execution/action_execution.rs"),
  admission: read("crates/services/src/agentic/runtime/service/handler/execution/runtime_tool_admission.rs"),
  registry: read("crates/services/src/agentic/runtime/runtime_tool_contract_registry.rs"),
  builder: read("crates/services/src/agentic/runtime/service/builder.rs"),
  catalog: read("crates/node/src/bin/hypervisor_daemon_routes/lifecycle_routes.rs"),
  tool: read("crates/types/src/app/agentic/tools/agent_tool.rs"),
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
  const execution = segment(
    candidate.action,
    "pub async fn handle_action_execution(",
    "let (mut foreground_window, target_app_hint) = prepare_tool_for_execution(",
  );
  const resolution = segment(candidate.admission, "fn resolve_contract(", "fn exact_grant_source(");
  const admission = segment(
    candidate.admission,
    "pub(super) async fn admit_runtime_tool_invocation(",
    "#[cfg(test)]",
  );
  const agentToolEnum = segment(candidate.tool, "pub enum AgentTool {", "// Keep `crate::app::ActionTarget`");
  const reservedToolNames = segment(
    candidate.tool,
    "pub const RESERVED_TOOL_NAMES",
    "/// Returns the canonical serialized tool name",
  );
  const typedToolNames = [...agentToolEnum.matchAll(/#\[serde\(rename = "([^"]+)"\)\]/g)]
    .map((match) => match[1]);

  require(
    execution.includes("admit_runtime_tool_invocation(") &&
      execution.includes("normalize_patch_build_verify_targeted_exec_tool(") &&
      execution.indexOf("normalize_patch_build_verify_targeted_exec_tool(") <
        execution.indexOf("admit_runtime_tool_invocation("),
    "universal_pre_invocation_gate_missing",
  );
  require(
    resolution.includes("runtime_tool_contract_registry") &&
      resolution.includes("resolve_current_for_name") &&
      resolution.includes("observed_runtime_tool_boundary") &&
      resolution.includes("observed_primitive_capabilities_for_action_target") &&
      resolution.includes("canonical_label"),
    "registry_resolution_or_boundary_comparison_missing",
  );
  require(
    admission.includes("exact_grant_source(") &&
      admission.includes("hex::encode(session_id)") &&
      admission.includes("step_index") &&
      admission.includes("primitive_capability_grants") &&
      admission.includes("authority_scope_grants") &&
      admission.includes("contract_admission_receipt_ref") &&
      admission.includes("arguments_hash") &&
      admission.includes("persist_receipt("),
    "bounded_grant_or_receipt_missing",
  );
  require(
    candidate.registry.includes("validate_admitted_runtime_tool_contract") &&
      candidate.registry.includes("resolve_exact(") &&
      candidate.registry.includes("revocations_by_hash") &&
      candidate.registry.includes("restore_snapshot("),
    "immutable_registry_lifecycle_missing",
  );
  require(
    candidate.registry.includes("canonical_jcs") &&
      candidate.registry.includes("runtime_tool_contract_canonical_hash_material"),
    "immutable_registry_canonical_bytes_missing",
  );
  require(
    candidate.builder.match(/default_seeded_registry\(\)/g)?.length >= 2 &&
      candidate.tool.includes("RESERVED_TOOL_NAMES"),
    "closed_native_seed_missing",
  );
  require(
    typedToolNames.length > 0 &&
      typedToolNames.every((name) => reservedToolNames.includes(`"${name}"`)) &&
      ["model__responses", "media__generate_image", "model_registry__load", "backend__health"]
        .every((name) => reservedToolNames.includes(`"${name}"`)),
    "closed_native_census_incomplete",
  );
  require(
    segment(candidate.catalog, "pub(crate) async fn handle_tools(", "/// GET /v1/hypervisor/core-taxonomy")
      .includes("current_released()"),
    "catalog_not_projected_from_registry",
  );
  return failures;
}

const failures = analyze(sources).map((code) => ({ code, detail: "source invariant failed" }));
const mutations = [
  ["action", "admit_runtime_tool_invocation(", "universal_pre_invocation_gate_missing"],
  ["admission", "resolve_current_for_name", "registry_resolution_or_boundary_comparison_missing"],
  ["admission", "observed_primitive_capabilities_for_action_target", "registry_resolution_or_boundary_comparison_missing"],
  ["admission", "persist_receipt(", "bounded_grant_or_receipt_missing"],
  ["registry", "revocations_by_hash", "immutable_registry_lifecycle_missing"],
  ["registry", "canonical_jcs", "immutable_registry_canonical_bytes_missing"],
  ["builder", "default_seeded_registry()", "closed_native_seed_missing"],
  ["tool", "        \"file__write\",\n", "closed_native_census_incomplete"],
  ["catalog", "current_released()", "catalog_not_projected_from_registry"],
];
for (const [file, needle, expected] of mutations) {
  const mutated = { ...sources, [file]: sources[file].replaceAll(needle, "removed_by_mutation") };
  if (!analyze(mutated).includes(expected)) {
    failures.push({ code: "mutation_false_green", detail: `${expected}: ${needle}` });
  }
}

for (const [packageName, filter, expected] of [
  ["ioi-services", "runtime_tool_contract_registry", "native_seed_covers_closed_tool_census"],
  ["ioi-services", "runtime_tool_admission", "destination_and_data_class_fail_closed"],
  ["ioi-services", "agentic::runtime::tools::contracts::tests", "polymorphic_screen_contract_uses_its_maximum_effect_boundary"],
  ["ioi-types", "browser_observation_tools_map_to_the_inspection_boundary", "browser_observation_tools_map_to_the_inspection_boundary"],
]) {
  const test = spawnSync(
    "cargo",
    ["test", "--locked", "-p", packageName, filter, "--lib", "--", "--nocapture"],
    { cwd: root, encoding: "utf8", maxBuffer: 16 * 1024 * 1024 },
  );
  if (test.status !== 0) {
    failures.push({ code: "behavioral_tests_failed", detail: (test.stderr || test.stdout).slice(-4000) });
  } else if (!(test.stdout || "").includes(expected)) {
    failures.push({ code: "focused_test_not_executed", detail: expected });
  }
}

if (failures.length) {
  console.error(JSON.stringify({ ok: false, schema_version: "ioi.check.runtime-tool-contract-admission.v1", failures }, null, 2));
  process.exit(1);
}
console.log(JSON.stringify({
  ok: true,
  schema_version: "ioi.check.runtime-tool-contract-admission.v1",
  universal_choke: "RuntimeAgentService.handle_action_execution",
  contract_owner: "immutable released RuntimeToolContract registry",
  mutation_probes: mutations.length,
}, null, 2));
