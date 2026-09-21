#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { emitVerifierCensus } from "./lib/verifier-census.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "..", "..", "..");
const read = (file) => fs.readFileSync(path.join(root, file), "utf8");
const sources = {
  router: read("crates/node/src/bin/hypervisor-daemon.rs"),
  lifecycle: read("crates/node/src/bin/hypervisor_daemon_routes/lifecycle_routes.rs"),
  operability: read("crates/node/src/bin/hypervisor_daemon_routes/operability_routes.rs"),
  registry: read("crates/services/src/agentic/runtime/runtime_tool_contract_registry.rs"),
  decision: read("crates/services/src/agentic/runtime/service/decision_loop/mod.rs"),
  policy: read("crates/services/src/agentic/runtime/service/policy.rs"),
  normalization: read("crates/node/src/bin/hypervisor_daemon_routes/mcp_normalization_routes.rs"),
  protocol: read("crates/drivers/src/mcp/protocol.rs"),
  stdio: read("crates/drivers/src/mcp/transport.rs"),
  manager: read("crates/drivers/src/mcp/mod.rs"),
  systemManifest: read("docs/architecture/_meta/schemas/autonomous-system-manifest.v1.schema.json"),
  systemGenesis: read("docs/architecture/_meta/schemas/autonomous-system-genesis.v1.schema.json"),
  sdk: read("packages/agent-sdk/src/substrate-client.ts"),
  cli: read("crates/cli/src/commands/mcp.rs"),
  developerDocs: read("apps/developers-ioi-ai/src/content/docs.tsx"),
};

const canonicalRoutes = [
  "/v1/threads/:id/mcp/status",
  "/v1/threads/:id/mcp/validate",
  "/v1/threads/:id/mcp/import",
  "/v1/threads/:id/mcp/servers",
  "/v1/threads/:id/mcp/servers/:server_id",
  "/v1/threads/:id/mcp/servers/:server_id/enable",
  "/v1/threads/:id/mcp/servers/:server_id/disable",
  "/v1/threads/:id/mcp/tools/search",
  "/v1/threads/:id/mcp/tools/:tool_id",
  "/v1/threads/:id/mcp/tools/:tool_id/invoke",
  "/v1/threads/:id/mcp/resources/search",
  "/v1/threads/:id/mcp/resources/:resource_id",
  "/v1/threads/:id/mcp/resources/:resource_id/read",
  "/v1/threads/:id/mcp/prompts/search",
  "/v1/threads/:id/mcp/prompts/:prompt_id",
  "/v1/threads/:id/mcp/prompts/:prompt_id/imports",
  "/v1/threads/:id/mcp/elicitation-requests",
  "/v1/threads/:id/mcp/elicitation-requests/:request_id/responses",
  "/v1/threads/:id/mcp/external-task-bindings",
  "/v1/threads/:id/mcp/external-task-bindings/:binding_id",
  "/v1/threads/:id/mcp/external-task-bindings/:binding_id/cancel",
  "/v1/threads/:id/mcp/apps/search",
  "/v1/threads/:id/mcp/apps/:app_id/descriptor",
  "/v1/threads/:id/mcp/serve",
];

function segment(text, start, end) {
  const from = text.indexOf(start);
  if (from < 0) return "";
  const to = text.indexOf(end, from + start.length);
  return text.slice(from, to < 0 ? text.length : to);
}

function analyze(candidate) {
  const failures = [];
  const require = (condition, code) => { if (!condition) failures.push(code); };
  const compatibilityInvoke = segment(
    candidate.router,
    "async fn handle_mcp_invoke(",
    "/// GET /v1/model-mount/mcp",
  );
  const canonicalInvoke = segment(
    candidate.lifecycle,
    "pub(crate) async fn handle_mcp_tool_invoke(",
    "/// GET /v1/mcp/servers",
  );
  const runtimeHost = segment(
    candidate.lifecycle,
    "pub(crate) async fn handle_runtime_host_session(",
    "#[cfg(test)]",
  );
  const canonicalImport = segment(
    candidate.lifecycle,
    "pub(crate) async fn handle_mcp_import(",
    "/// POST /v1/threads/:id/mcp/servers",
  );
  const canonicalRemoveDisable = segment(
    candidate.lifecycle,
    "pub(crate) async fn handle_mcp_remove(",
    "/// POST /v1/threads/:id/mcp (or /mcp/status)",
  );
  const canonicalEnable = segment(
    candidate.lifecycle,
    "pub(crate) async fn handle_mcp_enable(",
    "/// POST /v1/threads/:id/mcp/servers/:server_id/disable",
  );
  const mountedMcpRoutes = new Set(
    [...candidate.router.matchAll(/\.route\(\s*"([^"]*mcp[^"]*)"/gi)].map((match) => match[1]),
  );
  const classifications = segment(
    candidate.operability,
    "pub(crate) const MCP_ROUTE_CLASSIFICATIONS",
    "pub(crate) fn verify_mcp_route_classification(",
  );
  const classifiedMcpRoutes = new Set(
    [...classifications.matchAll(/"(\/v1\/[^"]*mcp[^"]*)"/gi)].map((match) => match[1]),
  );

  require(canonicalRoutes.every((route) => candidate.router.includes(`"${route}"`)), "canonical_route_set_incomplete");
  require(
    mountedMcpRoutes.size === classifiedMcpRoutes.size &&
      [...mountedMcpRoutes].every((route) => classifiedMcpRoutes.has(route)) &&
      candidate.router.includes("verify_mcp_route_classification()") &&
      candidate.operability.includes("MCP route classification drift"),
    "externally_reachable_mcp_route_unclassified",
  );
  // M01.10 (R-219): the typed-unavailable answer moved OUT of these two files into one builder that
  // validates against a registered contract before it serves. The routes still exist and still refuse;
  // what changed is that there is now exactly one place the shape can drift, and this check follows it.
  require(
    candidate.lifecycle.includes("handle_mcp_normalization_unavailable_root") &&
      candidate.lifecycle.includes("handle_mcp_normalization_unavailable_object") &&
      candidate.lifecycle.includes("mcp_normalization_routes::typed_unavailable(") &&
      candidate.normalization.includes('"status": if normalized { "normalized" } else { "typed_unavailable" }') &&
      candidate.normalization.includes('"authority_granted": false') &&
      candidate.normalization.includes('"receipt_identity_granted": false') &&
      candidate.normalization.includes("validate_architecture_contract("),
    "typed_unavailable_owner_mapping_missing",
  );
  require(
    candidate.operability.includes("mcp_gateway_profile_unavailable") &&
      candidate.operability.includes("mcp_normalization_routes::gateway_typed_unavailable(") &&
      candidate.normalization.includes('"HypervisorMCPGatewayProfile"') &&
      !candidate.operability.includes("FORWARDED_AUTH_HEADERS") &&
      candidate.lifecycle.includes('"status": "unadmitted_candidates"') &&
      candidate.lifecycle.includes('"tools": []'),
    "gateway_or_connector_candidate_bypass_present",
  );
  require(
    candidate.systemManifest.includes('"mcp_gateway_requirements": {') &&
      candidate.systemManifest.includes("^mcp-gateway-requirement://") &&
      !candidate.systemManifest.includes('"mcp_gateway_profiles"') &&
      candidate.systemGenesis.includes('"mcp_gateway_profiles": {') &&
      candidate.systemGenesis.includes("^mcp-gateway://"),
    "package_requirement_live_profile_separation_missing",
  );
  require(
    segment(candidate.sdk, "async threadMcpStatus(", "async importThreadMcp(")
      .includes('"GET"') &&
      candidate.sdk.includes("/mcp/tools/${encodePath(toolId)}/invoke") &&
      candidate.cli.includes("thread_id: String") &&
      candidate.cli.includes('"arguments": input') &&
      !candidate.developerDocs.includes("/v1/mcp/tools/{'{tool_id}'}/invoke"),
    "stable_client_route_drift",
  );
  require(
    compatibilityInvoke.includes('get("thread_id")') &&
      compatibilityInvoke.includes("lifecycle_routes::handle_mcp_tool_invoke(") &&
      !compatibilityInvoke.includes('"status": "executed"') &&
      !compatibilityInvoke.includes("execution_receipt"),
    "compatibility_route_bypasses_canonical_invoker_or_claims_execution",
  );
  require(
    canonicalInvoke.includes("runtime_tool_contract_registry") &&
      canonicalInvoke.includes("thread_mcp_server_binds_contract") &&
      canonicalInvoke.includes("mcp_tool_not_bound_to_thread") &&
      canonicalInvoke.includes("runtime_host::handle_runtime_host_session") &&
      canonicalInvoke.includes('"final_invoker": "RuntimeAgentService.handle_action_execution"') &&
      canonicalInvoke.includes("AgentActionResult") &&
      ["file_write", "shell_run", "browser_navigate", "mcp_tool_call"]
        .every((directive) => canonicalInvoke.includes(`"${directive}"`)) &&
      canonicalInvoke.includes("host_body.remove(conflicting_directive)"),
    "canonical_invocation_bypasses_final_invoker_or_contract",
  );
  require(
    runtimeHost.indexOf("mcp_tool_call") >= 0 &&
      runtimeHost.indexOf("mcp_tool_call") < runtimeHost.indexOf("execute_authority_gate(") &&
      runtimeHost.includes("install_constrained_extension_invoke_policy") &&
      candidate.lifecycle.includes("with_mcp_manager") &&
      candidate.lifecycle.includes("with_runtime_tool_contract_registry"),
    "runtime_host_mcp_admission_order_or_shared_owner_missing",
  );
  require(
    candidate.registry.includes("pub fn admit_mcp_server_tools(") &&
      candidate.registry.includes("let mut candidate = self.clone();") &&
      candidate.registry.includes("if current.contract == contract") &&
      candidate.registry.includes("contract.predecessor_revision_ref = Some") &&
      candidate.registry.includes("*self = candidate;"),
    "descriptor_admission_not_atomic",
  );
  require(
    canonicalImport.includes("live_mcp_server_candidates") &&
      canonicalImport.includes("admit_live_mcp_candidates") &&
      candidate.lifecycle.includes("super::start_and_admit_mcp_server") &&
      candidate.lifecycle.includes('Some("development" | "production")') &&
      candidate.lifecycle.includes("strip_caller_mcp_admission_claims") &&
      candidate.lifecycle.includes("bind_live_mcp_admissions") &&
      candidate.lifecycle.includes("thread_mcp_projection_servers") &&
      candidate.lifecycle.includes("thread_mcp_server_has_daemon_binding") &&
      canonicalRemoveDisable.match(/if owns_live_binding/g)?.length === 2 &&
      canonicalEnable.includes("admit_live_mcp_candidates") &&
      candidate.manager.includes("pub async fn stop_server(") &&
      candidate.manager.includes("transport.shutdown().await?") &&
      canonicalRemoveDisable.match(/stop_server\(&server_id\)/g)?.length === 2,
    "canonical_import_not_live_or_teardown_not_deterministic",
  );
  require(
    candidate.decision.includes("fn maybe_typed_runtime_mcp_tool_call(") &&
      candidate.decision.includes("RUNTIME_ROUTE_MCP_TOOL_MARKER") &&
      candidate.policy.includes("install_constrained_extension_invoke_policy"),
    "typed_extension_dispatch_missing",
  );
  require(
    candidate.protocol.includes('MCP_PROTOCOL_VERSION: &str = "2025-06-18"') &&
      candidate.stdio.includes("MCP_PROTOCOL_VERSION") &&
      candidate.stdio.includes("negotiated != MCP_PROTOCOL_VERSION") &&
      candidate.lifecycle.includes("ioi_drivers::mcp::protocol::MCP_PROTOCOL_VERSION") &&
      candidate.lifecycle.includes("MCP initialize negotiated unsupported protocolVersion") &&
      ![candidate.protocol, candidate.stdio, candidate.lifecycle, candidate.router].some((text) => text.includes("2024-11-05")),
    "transport_protocol_revision_drift",
  );
  return failures;
}

// M01.10 (R-219): this gate had no census, no floor row and no CI job — it could be deleted, emptied or
// quietly reduced to three assertions and nothing would have said so. Every `require` and every mutation
// probe is now a NAMED assertion, counted and floored.
const census = [];
const ASSERTION_CODES = [
  "canonical_route_set_incomplete",
  "externally_reachable_mcp_route_unclassified",
  "typed_unavailable_owner_mapping_missing",
  "gateway_or_connector_candidate_bypass_present",
  "package_requirement_live_profile_separation_missing",
  "stable_client_route_drift",
  "compatibility_route_bypasses_canonical_invoker_or_claims_execution",
  "canonical_invocation_bypasses_final_invoker_or_contract",
  "runtime_host_mcp_admission_order_or_shared_owner_missing",
  "descriptor_admission_not_atomic",
  "canonical_import_not_live_or_teardown_not_deterministic",
  "typed_extension_dispatch_missing",
  "transport_protocol_revision_drift",
];

const sourceFailures = analyze(sources);
for (const code of ASSERTION_CODES) {
  census.push({ name: `source invariant holds: ${code}`, pass: !sourceFailures.includes(code) });
}
const failures = sourceFailures.map((code) => ({ code, detail: "source invariant failed" }));
const mutations = [
  ["router", `        .route(\n            "${canonicalRoutes.at(-1)}",`, "canonical_route_set_incomplete"],
  ["operability", '    ("/v1/model-mount/mcp", "compatibility_projection"),\n', "externally_reachable_mcp_route_unclassified"],
  ["normalization", "validate_architecture_contract(", "typed_unavailable_owner_mapping_missing"],
  ["lifecycle", "mcp_normalization_routes::typed_unavailable(", "typed_unavailable_owner_mapping_missing"],
  ["operability", "mcp_normalization_routes::gateway_typed_unavailable(", "gateway_or_connector_candidate_bypass_present"],
  ["systemManifest", '"mcp_gateway_requirements": {', "package_requirement_live_profile_separation_missing"],
  ["cli", "thread_id: String", "stable_client_route_drift"],
  ["router", "lifecycle_routes::handle_mcp_tool_invoke(", "compatibility_route_bypasses_canonical_invoker_or_claims_execution"],
  ["lifecycle", '"final_invoker": "RuntimeAgentService.handle_action_execution"', "canonical_invocation_bypasses_final_invoker_or_contract"],
  ["lifecycle", "if !thread_mcp_server_binds_contract(\n        &st,\n        &thread_id,\n        &server_id,", "canonical_invocation_bypasses_final_invoker_or_contract"],
  ["lifecycle", '        "browser_navigate",\n', "canonical_invocation_bypasses_final_invoker_or_contract"],
  ["lifecycle", "install_constrained_extension_invoke_policy(&mut state, session_id, tool_name)", "runtime_host_mcp_admission_order_or_shared_owner_missing"],
  ["registry", "let mut candidate = self.clone();", "descriptor_admission_not_atomic"],
  ["lifecycle", "admit_live_mcp_candidates(&st, live_candidates)", "canonical_import_not_live_or_teardown_not_deterministic"],
  ["manager", "transport.shutdown().await?", "canonical_import_not_live_or_teardown_not_deterministic"],
  ["decision", "fn maybe_typed_runtime_mcp_tool_call(", "typed_extension_dispatch_missing"],
  ["protocol", 'MCP_PROTOCOL_VERSION: &str = "2025-06-18"', "transport_protocol_revision_drift"],
];
for (const [file, needle, expected] of mutations) {
  const mutated = { ...sources, [file]: sources[file].replace(needle, "removed_by_mutation") };
  const planted = mutated[file] !== sources[file];
  const caught = analyze(mutated).includes(expected);
  census.push({ name: `planted defect goes red on target: ${expected} ← ${file}:${needle.slice(0, 60)}`, pass: planted && caught });
  if (!planted) failures.push({ code: "mutation_planted_nothing", detail: `${expected}: ${needle}` });
  else if (!caught) failures.push({ code: "mutation_false_green", detail: `${expected}: ${needle}` });
}

emitVerifierCensus({ verifierId: "mcp-transport-normalization", sourceUrl: import.meta.url, results: census });

if (failures.length) {
  console.error(JSON.stringify({
    ok: false,
    schema_version: "ioi.check.mcp-transport-normalization.v1",
    executed_assertions: census.length,
    failures,
  }, null, 2));
  process.exit(1);
}

console.log(JSON.stringify({
  ok: true,
  schema_version: "ioi.check.mcp-transport-normalization.v1",
  canonical_route_count: canonicalRoutes.length,
  source_protocol_version: "2025-06-18",
  final_invoker: "RuntimeAgentService.handle_action_execution",
  mutation_probes: mutations.length,
  executed_assertions: census.length,
}, null, 2));
