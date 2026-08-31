#!/usr/bin/env node
// ADR-0035 SOURCE CONTRACT — a fast, mechanically derived companion to the live owner-model gates.
//
// The live suites prove behavior and material absence. This gate makes the implementation shape
// mutation-addressable: every ADR ruling and each named handle has a stable failure code, while the
// router census derives its closed world from registrations and transitive Rust calls. The mutation
// battery copies the relevant source tree to a temporary root, plants one implementation defect at
// a time, and requires this gate to go RED on the named code.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { deriveEnvironmentOwnerCensus } from "./lib/environment-owner-source-census.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REAL_ROOT = path.resolve(HERE, "..", "..", "..");
const ROOT = path.resolve(process.env.IOI_OWNER_MODEL_ROOT || REAL_ROOT);
const routeDir = path.join(ROOT, "crates/node/src/bin/hypervisor_daemon_routes");
const read = (relative) => fs.readFileSync(path.join(ROOT, relative), "utf8");
const src = {
  root: read("crates/node/src/bin/hypervisor-daemon.rs"),
  env: read("crates/node/src/bin/hypervisor_daemon_routes/environment_routes.rs"),
  binding: read("crates/node/src/bin/hypervisor_daemon_routes/binding_routes.rs"),
  agentops: read("crates/node/src/bin/hypervisor_daemon_routes/agentops_routes.rs"),
  editor: read("crates/node/src/bin/hypervisor_daemon_routes/editor_routes.rs"),
  editorProxy: read("crates/node/src/bin/hypervisor_daemon_routes/editor_proxy.rs"),
  lifecycle: read("crates/node/src/bin/hypervisor_daemon_routes/lifecycle_routes.rs"),
  managed: read("crates/node/src/bin/hypervisor_daemon_routes/managed_runtime_routes.rs"),
  supervisor: read("crates/node/src/bin/hypervisor_daemon_routes/supervisor_routes.rs"),
  census: read("apps/hypervisor/scripts/lib/environment-owner-source-census.mjs"),
  custody: read("apps/hypervisor/scripts/verify-hypervisor-environment-custody.mjs"),
  live: read("apps/hypervisor/scripts/verify-hypervisor-env-lease-authority.mjs"),
};

function matching(source, start) {
  let depth = 0;
  let string = false;
  let rawStringHashes = null;
  let escaped = false;
  let lineComment = false;
  let blockDepth = 0;
  for (let index = start; index < source.length; index += 1) {
    const here = source[index];
    const next = source[index + 1] ?? "";
    if (lineComment) { if (here === "\n") lineComment = false; continue; }
    if (blockDepth) {
      if (here === "/" && next === "*") { blockDepth += 1; index += 1; }
      else if (here === "*" && next === "/") { blockDepth -= 1; index += 1; }
      continue;
    }
    if (rawStringHashes !== null) {
      const terminator = `"${"#".repeat(rawStringHashes)}`;
      if (source.startsWith(terminator, index)) {
        index += terminator.length - 1;
        rawStringHashes = null;
      }
      continue;
    }
    if (string) {
      if (escaped) escaped = false;
      else if (here === "\\") escaped = true;
      else if (here === '"') string = false;
      continue;
    }
    if (here === "/" && next === "/") { lineComment = true; index += 1; continue; }
    if (here === "/" && next === "*") { blockDepth = 1; index += 1; continue; }
    if (here === "r" && (next === '"' || next === "#")) {
      let cursor = index + 1;
      while (source[cursor] === "#") cursor += 1;
      if (source[cursor] === '"') {
        rawStringHashes = cursor - index - 1;
        index = cursor;
        continue;
      }
    }
    if (here === "'") {
      const width = next === "\\" ? 3 : 2;
      if (source[index + width] === "'") { index += width; continue; }
    }
    if (here === '"') { string = true; continue; }
    if (here === "{") depth += 1;
    else if (here === "}" && --depth === 0) return index;
  }
  return -1;
}

function body(source, name) {
  const declaration = new RegExp(`\\bfn\\s+${name}\\s*(?:<[^>{}]*>)?\\s*\\(`, "u").exec(source);
  if (!declaration) return "";
  const open = source.indexOf("{", declaration.index);
  const close = matching(source, open);
  return close < 0 ? "" : source.slice(open + 1, close);
}

const results = [];
const check = (code, condition, detail) => results.push({ code, pass: !!condition, detail });
const hasAll = (text, needles) => needles.every((needle) => text.includes(needle));
const census = deriveEnvironmentOwnerCensus(ROOT);
const route = (method, pathname) => census.routes.find((item) => item.method === method && item.path === pathname);
const ownerRoute = (method, pathname) => route(method, pathname)?.classification === "owner_authorized";
const aggregateRoutes = census.routes
  .filter((item) => item.classification === "aggregate_only")
  .map((item) => item.handler)
  .sort();
const policyContextRoutes = census.routes
  .filter((item) => item.classification === "policy_context_only")
  .map((item) => item.handler)
  .sort();

const create = body(src.env, "handle_environment_create");
const get = body(src.env, "handle_environment_get");
const action = body(src.env, "handle_environment_action");
const canonical = body(src.env, "canonical_environment_id");
const ownerIdentity = body(src.env, "authorize_environment_owner_identity");
const disposal = body(src.env, "authorize_environment_disposal");
const list = body(src.env, "handle_environments_list");
const workrunCreate = body(src.env, "handle_workrun_create");
const workrunExecute = body(src.env, "handle_workrun_execute");
const envFiles = body(src.binding, "handle_env_files");
const terminalCreate = body(src.binding, "handle_terminal_create");
const conversationCreate = body(src.agentops, "handle_conversation_create");
const editorCreate = body(src.editor, "handle_editor_service_create");
const opsMint = body(src.supervisor, "handle_env_ops_lease");
const opsConsumer = body(src.supervisor, "lease_authorizes_env_ops");
const previewAuth = body(src.lifecycle, "preview_request_authorized");
const principalDelete = body(src.lifecycle, "handle_principal_delete");
const managedCapture = body(src.managed, "capture_environment_backup");
const portExpose = body(src.env, "handle_env_port_expose");
const portTargetFence = body(src.env, "admitted_environment_port_target");

check("R1_DERIVED_CLOSED_WORLD",
  census.registered_route_handlers === 1069 && census.workspace_route_handlers === 38
    && census.routes.length === 44 && census.unresolved.length === 0 && census.unclassified.length === 0
    && ownerRoute("GET", "/") && ownerRoute("GET", "/*preview_path")
    && aggregateRoutes.join(",") === "operability_routes::handle_operability_metrics,orchestration_routes::handle_placement_metrics"
    && policyContextRoutes.join(",") === [
      "placement_failover_routes::handle_failover_evaluate",
      "placement_failover_routes::handle_failover_run",
      "provider_routes::handle_provider_op",
      "workload_effect_boundary::handle_governed_capability_consume",
    ].join(",")
    && hasAll(src.census, ["rawStringHashes", "if (here === \"r\"", "if (here === \"'\")", "AGGREGATE_ONLY_HANDLERS", "invalidAggregateMarker", "POLICY_CONTEXT_FUNCTION", "invalidPolicyContextMarker", "contribution_read_handlers"]),
  `registered=${census.registered_route_handlers} workspace=${census.workspace_route_handlers} candidates=${census.routes.length} unresolved=${census.unresolved.length} unclassified=${census.unclassified.length}`);

check("R2_ONE_CREATE_SEAM",
  census.routes.filter((item) => item.handler === "environment_routes::handle_environment_create").length === 1
    && (create.match(/\bnew_env\s*\(/gu) || []).length === 1
    && !get.includes("new_env(") && !action.includes("new_env("),
  "exactly one registered handler and one production new_env call; GET/action contain none");

check("R3_DAEMON_MINT_AND_COLLISION",
  hasAll(create, ["environment_id_server_minted", 'gen_opaque("env")', "for _ in 0..16", "load_env", "read_request_scope", "environment_id_collision"]),
  "caller ids refused; opaque mint retries only unoccupied record+pin coordinates");

const bindAt = create.indexOf("bind_request_resource_scope");
const persistAt = create.indexOf("persist_env");
check("R4_BIND_PRECEDES_BYTES",
  bindAt >= 0 && persistAt > bindAt && create.includes('environment-owner:{id}'),
  `bind_index=${bindAt} persist_index=${persistAt}`);

check("R5_CANONICAL_REJECTION",
  hasAll(canonical, ["is_normalization_safe", "safe_id(id) != id", "environment_id_not_canonical"])
    && ownerIdentity.includes("canonical_environment_id")
    && managedCapture.includes("authorize_environment_owner_identity"),
  "one rejecting edge canonicalizer feeds shared pin authorization, including managed backup");

check("R6_PIN_IS_AUTHORITY",
  hasAll(ownerIdentity, ["authorize_request_resource_scope", "ENVIRONMENT_SCOPE_KIND"])
    && get.includes("authorize_environment_owner_identity") && action.includes("authorize_environment_owner_identity")
    && !ownerIdentity.includes('env["owner') && !ownerIdentity.includes("load_env"),
  "environment record fields never grant access; the immutable request scope does");

check("R7_LEGACY_ADMIN_DISPOSAL_ONLY",
  hasAll(disposal, ["read_request_scope", "require_authenticated_org_admin", "legacy_unadopted", "commit_environment_disposal_receipt"])
    && !disposal.includes("bind_request_resource_scope"),
  "legacy coordinates remain unadopted; administrators receive disposal only with receipts");

check("R8_CUSTODY_ASSERTIONS_FLIPPED",
  src.custody.includes('import { deriveEnvironmentOwnerCensus } from "./lib/environment-owner-source-census.mjs";')
    && !src.custody.includes("NAMED_UNOWNED")
    && ["/v1/hypervisor/snapshots", "/v1/hypervisor/snapshots/:id/restore", "/v1/hypervisor/backups"].every((p) => src.custody.includes(p)),
  "capture/restore harm probes and the derived owner census are live, with no named-unowned exception");

check("R9_OWNER_SCOPED_ENUMERATION",
  hasAll(list, ["authorized_request_resource_refs", "ENVIRONMENT_SCOPE_KIND", "owned.contains(id)"]),
  "GET /environments filters durable records through the caller's pin set");

check("R10_DEPROVISIONED_OWNER_DISPOSABLE",
  hasAll(principalDelete, ['p["status"] = json!("deactivated")', 'remove_record(&st.data_dir, "sessions"'])
    && action.includes('matches!(action.as_str(), "stop" | "archive" | "delete")')
    && action.includes("authorize_environment_disposal"),
  "deactivation revokes sessions while the environment plane retains administrator disposal");

check("R11_THREE_UNAUTHENTICATED_SURFACES_CLOSED",
  hasAll(opsMint, ["authorize_environment_owner", "&identity.principal_ref", '"environment.ops"'])
    && hasAll(opsConsumer, ["ENV_OPS_ACTION", "Some(scope.principal_ref.as_str())"])
    && hasAll(previewAuth, ["capability_lease_status", "query.get(\"lease\")", "Some(state.capability_lease_ref.as_str())"])
    && src.editorProxy.includes("let authed = lease_active && token_ok;"),
  "ops minter+consumer, preview, and editor proxy are all exact-authority gates");

const portFenceAt = portExpose.indexOf("admitted_environment_port_target");
const portLeaseAt = portExpose.indexOf("issue_capability_lease");
check("M032_PORT_TARGET_FENCE",
  portFenceAt >= 0 && portLeaseAt > portFenceAt
    && hasAll(portTargetFence, [
      'read_record_dir(data_dir, "environments")',
      'Err("environment_port_not_admitted")',
      'Err("environment_port_target_owned_by_another_environment")',
      "environment_port_record_target(port_record)",
    ])
    && portExpose.includes("target_port,") && !portExpose.includes("port as u16,")
    && hasAll(src.live, ["M03.2 CROSS-CONSUMER NEGATIVE", "M03.2 POSITIVE CONTROL"]),
  `fence_index=${portFenceAt} lease_index=${portLeaseAt} target_is_server_derived=${portExpose.includes("target_port,")}`);

check("V4_SEVEN_HANDLES",
  get.includes("authorize_environment_owner_identity")
    && terminalCreate.includes("authorize_environment_owner")
    && opsMint.includes("authorize_environment_owner")
    && previewAuth.includes("capability_lease_status")
    && workrunCreate.includes("authorize_environment_owner_request")
    && conversationCreate.includes("authorize_environment_owner")
    && editorCreate.includes("authorize_environment_owner"),
  "environment, terminal, ops lease, preview, workrun, conversation, and editor handles authorize");

check("V5_CAPTURE_FAMILIES",
  ownerRoute("POST", "/v1/hypervisor/snapshots") && ownerRoute("POST", "/v1/hypervisor/backups")
    && ownerRoute("POST", "/v1/hypervisor/environments/:id/backups"),
  "legacy snapshot/backup and managed backup are in the derived owner-authorized world");

check("V6_NONEXISTENT_IS_404_NO_CREATE",
  get.indexOf("resolve_environment_request_identity") < get.indexOf("load_env")
    && get.indexOf("load_env") < get.indexOf("authorize_environment_owner_identity")
    && get.includes("environment_not_found") && !get.includes("new_env(")
    && action.indexOf("resolve_environment_request_identity") < action.indexOf("load_env")
    && action.includes("environment_not_found"),
  "identity resolves first; missing GET/action returns 404 before authorization and never creates");

check("V12_WORKRUN_NO_SIDE_EFFECT_BEFORE_AUTH",
  workrunCreate.indexOf("authorize_environment_owner_request") >= 0
    && workrunCreate.indexOf("authorize_environment_owner_request") < workrunCreate.indexOf("ensure_git_repo")
    && workrunExecute.includes("authorize_environment_owner_identity"),
  "workrun create/execute authorize before Git/workspace mutation");

check("V15_UNADOPTED_TYPED_REFUSAL",
  disposal.includes('"environment_unadopted"') && disposal.includes("scope.is_none()"),
  "ordinary legacy access is typed unadopted rather than merely not-yours");

check("V17_ADMIN_CANNOT_READ_OR_WRITE",
  !get.includes("authorize_environment_disposal") && envFiles.includes("authorize_environment_owner")
    && action.includes("authorize_environment_disposal"),
  "administrator bypass exists on disposal actions only, never GET or env-files");

let mutationManifest = null;
try { mutationManifest = JSON.parse(read("apps/hypervisor/environment-owner-model.mutants.v1.json")); } catch { /* reported below */ }
check("V18_MUTATION_FLOOR",
  mutationManifest?.schema_version === "ioi.hypervisor.environment-owner-model-mutants.v1"
    && mutationManifest?.expected_mutations === 23 && mutationManifest?.anchors?.length === 23
    && new Set(mutationManifest?.anchors?.map((anchor) => anchor.id)).size === 23
    && mutationManifest?.anchors?.every((anchor) => anchor.red_on && anchor.find && anchor.replace && anchor.anchor_file),
  `expected=23 actual=${mutationManifest?.anchors?.length ?? 0}`);

for (const result of results) {
  console.log(`${result.pass ? "PASS" : "FAIL"} [${result.code}] ${result.detail}`);
}
const failed = results.filter((result) => !result.pass);
console.log(`\n${results.length - failed.length}/${results.length} ADR-0035 source assertions passed`);
process.exit(failed.length ? 1 : 0);
