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
  // Re-pinned 2026-09-14 (M08.10 slice B) from 1132 to 1134 registered handlers: the extension
  // registration route `.../installations/:installation_id/registration` carries TWO handlers on
  // ONE path — POST admits the v2 registration over an installed binding, GET reads it or the
  // typed absence — so this census moves by 2 while the distinct-path census in
  // verify-hypervisor-named-gap-truth.mjs moves by 1, and both pins moved in the same commit as
  // the route. WORKSPACE HANDLERS (40) AND CANDIDATES (47) HELD: Applications admitting an
  // extension registration is a package-plane act over admitted release and binding truth, not an
  // environment-plane owner act and not a new owner-resolvable environment surface; unresolved 0,
  // unclassified 0.
  // Re-pinned 2026-09-14 (M09.11) from 1130 to 1132 registered handlers: the machine-operation
  // plane adds ONE route path carrying TWO handlers — POST to submit a proposal, GET to read what
  // was recorded — so this census moves by 2 while the distinct-path census beside it moves by 1.
  // That asymmetry is the whole reason the two pins exist separately, and the other pin's comment
  // says to come looking here; it was right.
  // WORKSPACE HANDLERS (40) AND CANDIDATES (47) DID NOT MOVE, and I nearly recorded that they did.
  // The machine plane is daemon-owned end to end: a workspace handler for it would be exactly the
  // client-side authority ACC-20 clause 5 refuses by name, and the candidate population is about
  // owner-resolvable environment surfaces, which this plane does not add to.
  // Re-pinned 2026-09-14 (M07.5) from 1136/40/47, +1 to the REGISTERED bucket only:
  // `handle_usage_aggregate`, the one handler on the one new economics path (so
  // `check:named-gap-truth` and this census move by one each, in the SAME commit as the route).
  // Workspace 40 and candidates 47 HELD: a usage aggregate reads the economics plane's own
  // chains and touches no environment surface.
  // Re-pinned 2026-09-14 (M08.10 slice C) from 1134/40/47, +2 to the REGISTERED bucket only:
  // `handle_installation_serving_binding_get` and `handle_installation_serving_binding_create`,
  // the two handlers on the one new serving-binding path (so `check:named-gap-truth` moves by one
  // while this census moves by two, both in the SAME commit as the route). Workspace 40 and
  // candidates 47 HELD: the serving binding reads the DomainApp runtime through that plane's own
  // published fold and touches no environment surface, so it is neither a workspace handler nor
  // an owner-resolvable environment candidate.
  // Re-pinned 2026-09-13 (M13.10) from 1130/39/46: registered handlers HELD at 1130 while workspace
  // 39 -> 40 and candidates 46 -> 47. No route was added. `handle_session_execute` now reads the
  // environment record to resolve the execution venue for its receipt (ADR 0053 § 2), which makes
  // it an environment-plane CONSUMER, and this census sees consumers rather than routes. The
  // registered-handler count holding is the evidence that this is a new read and not a new surface.
  // Re-pinned 2026-09-13 (M09.3) from 1129/38/45, +1 to ALL THREE: the port revocation act,
  // `POST /v1/hypervisor/environments/:id/ports/:port/revoke`. Unlike M07.4's candidate lane —
  // where the note below records `workspace` and `candidates` holding as the evidence that only the
  // registered bucket moved — this route IS an environment-plane owner act, so all three buckets
  // moving together is the evidence that it was classified as one rather than slipping in as
  // generic surface. A revocation that did not register as an environment owner would be authority
  // living somewhere the census cannot see it.
  // Re-pinned 2026-09-12 (M04.10) from 1125, +1: the per-dimension work-reservation admission.
  //
  // TWO GATES COUNT ROUTES, AND THE OTHER ONE WAS MOVED WITHOUT THIS ONE. `check:named-gap-truth`
  // pins `registeredRoutes` and this file pins `registered_route_handlers`; the M04.10 commit moved
  // the first and not the second, so CI caught a pin miss ONE COMMIT AFTER the same class of miss
  // was written up as a trap. The pre-push sweep that was built to prevent it ran the other gate
  // and not this one — the remedy had the same gap as the defect. A future route addition should
  // expect BOTH numbers to move, and the sweep should enumerate the gates rather than recall them.
  // Re-pinned 2026-09-12 (M07.4 items 2b and 2c) from 1122, +3. The model-route CANDIDATE lane
  // registered three handlers: `POST /model-routes/price-schedules` and
  // `GET /model-routes/price-schedules/:id` admit and read expiring advisory price evidence, and
  // `POST /model-routes/cost-comparison` returns an advisory ranking. NONE is a new environment
  // owner and none is a policy-context read of the environment plane: the lane carries evidence a
  // ranking may read and authorizes nothing, which is a const `advisory_only: true` in both of its
  // registered contracts rather than a claim made here. `workspace` (38) and `candidates` (45) are
  // unchanged, which is the evidence that only the registered-handler bucket moved.
  // Re-pinned 2026-09-08 (basis 1f6c5ac3e) from 1097/44 at 7c63a63ec: eleven registered handlers
  // were added by 49eecf0bc (decentralized-cloud job primitive: cloud-jobs list/create/get/execute
  // — execute is a POLICY_CONTEXT read of the environment plane, classified by its own marker),
  // f4e3e9907 (admitted release change plans: list/admit/get/action), and 1f6c5ac3e (the
  // attach-time standing lease bind/revoke and the capability-account read). None is a new
  // owner-authorized environment route or a second create seam; every route resolves and
  // classifies (unresolved 0, unclassified 0).
  //
  // Re-pinned 2026-09-09 (basis 2162403ce) from 1108: c80621ac2 (M08.13/M08.14) registered exactly
  // two handlers, the model-mount MCP `act` tool's list and invoke. Neither is an environment
  // route and neither is a create seam: both delegate to the connector-invoke draw-down gate,
  // which is why the candidate count is unchanged at 45. Derived, not adjusted to fit — the
  // growth is exactly those two and unresolved/unclassified are still 0.
  //
  // Re-pinned 2026-09-12 (basis 8315d8128) from 1110: a4f6987d9 (M09.1, HypervisorProjectDiscovery
  // Proposal) registered exactly four handlers in project_discovery_routes.rs — proposal admit,
  // acceptance admit, proposal get, proposal list. None is an environment route and none is a
  // create seam: discovery proposes and STOPS (the acceptance is a separate admitted successor on
  // the owner-scoped write path), so the candidate count is unchanged at 45 and unresolved and
  // unclassified are still 0. Found by CI on 2026-09-12, not by the landing commit: the M09.1
  // session did not run this check, and this job's contract block masked it for four runs.
  //
  // Re-pinned 2026-09-12 (leg 1, M03.8) from 1114: the device-held wallet-principal seam registers
  // exactly four handlers — provisioning admit, list, get, and the binding-state read. None is an
  // environment route and none is a create seam: the admit goes through the shared owner-scoped
  // write path and the binding-state read calls wallet.network rather than writing anything, so the
  // candidate count is unchanged at 45 and unresolved and unclassified are still 0. (Three routes
  // are mounted; the list and admit share one path, which the census counts as two handlers.)
  // 1118 -> 1122 (2026-09-12, M07.3). The provider-spend reconciliation plane registers three
  // paths, one of which carries two methods, and the router counts handlers rather than paths —
  // so four. Moved in the SAME COMMIT as the routes, like every other pin this program touched.
  // 1126 -> 1129 (2026-09-13, M09.2): THREE handlers across the two new paths — the startup-plan
  // lane carries both a GET and a POST, and the standalone resolution lane a POST. This census
  // counts HANDLERS where `check:named-gap-truth` counts distinct PATHS, which is why the two move
  // by different amounts on the same change and why moving one gives no hint the other needs it.
  // 1201 -> 1209 (2026-09-16, M03.16): EIGHT handlers — the connection ceremony's start and complete,
  // the inventory, get, dependents, verify, reauthorize and disconnect — on eight distinct paths
  // (`check:named-gap-truth` 932 -> 940 in this same commit). `workspace` (40) and `candidates`
  // (47) are unchanged: these routes own no environment route and serve no workspace lane.
  // 1209 -> 1216 (2026-09-16, M09.7): SEVEN handlers of route_assurance_routes.rs — the node-enforcement
  // observation's admit, list and get, the coverage read, and the assurance claim's admit, get and
  // inventory — on five distinct paths (`check:named-gap-truth` 940 -> 945 in this same commit: the
  // observation path and the per-route assurance path each carry a GET and a POST). `workspace` (40)
  // and `candidates` (47) are unchanged: nothing here is an environment route or a workspace lane.
  // 1216 -> 1219 (2026-09-16, R-172 slice S1): THREE handlers of system_record_routes.rs — the
  // System-scoped record seam's admit, list and get — on two distinct paths (`check:named-gap-truth`
  // 945 -> 947 in this same commit). `workspace` (40) and `candidates` (47) are unchanged.
  // 1197 -> 1201 (2026-09-16, M06.9): FOUR handlers — the lineage walk, the impact record's admit,
  // query and get — on three distinct paths (`check:named-gap-truth` 929 -> 932 in this same
  // commit). `workspace` (40) and `candidates` (47) are unchanged: these routes own no environment
  // route and serve no workspace lane, so only the registered bucket moved.
  // 1194 -> 1197 (2026-09-15, M10.2): THREE handlers — the role binding's admit and get, and the
  // derived candidate archive — on two distinct paths (`check:named-gap-truth` 927 -> 929 in this
  // same commit). `workspace` (40) and `candidates` (47) are unchanged: these routes own no
  // environment route and serve no workspace lane, so only the registered bucket moved.
  // 1174 -> 1194 (2026-09-15, M10.4): TWENTY handlers, the governed evaluation plane — suite
  // create/query/get/revise/release, evaluator create/query/get/revise/transition/impact, run
  // admit/query/get, result admit/query/get, continuity run/query/get. Sixteen distinct paths
  // (`check:named-gap-truth` 911 -> 927 in this same commit) because four collection paths carry
  // both GET and POST. `workspace` (40) and `candidates` (47) are unchanged: these routes own no
  // environment route and serve no workspace lane, so only the registered bucket moved. Every
  // handler resolves its caller through the shared write path or the request-identity resolver.
  // 1145 -> 1174 (2026-09-15, M10.1): TWENTY-NINE handlers, the bounded improvement campaign spine
  // — governance-profile admit/query/revision, agenda admit/query/revision/release, campaign
  // create/query/get/admit/start/pause/stop, epoch create/get/freeze/activate/challenge/close/
  // invalidate, exposure get/reserve/spend/release/rotate, cutoff emit/list and the upgrade-proposal
  // handoff. Twenty-five distinct paths (`check:named-gap-truth` 886 -> 911 in this same commit)
  // because four paths carry both GET and POST. `workspace` (40) and `candidates` (47) are
  // unchanged: these routes own no environment route and serve no workspace lane, which is the
  // evidence that only the registered bucket moved. Every handler resolves its caller through
  // `require_write_caller` or `resolve_request_identity` before reading a record, so none joins
  // the admission-evidence audit's legacy baseline.
  // 1138 -> 1145 (2026-09-14, M04.11): SEVEN handlers, the GoalRun-owned ContextLease and
  // ContextHandoff lifecycle — lease admit, narrow, revoke and resolution, handoff admit, accept
  // and reject. Here handlers and distinct paths move by the SAME amount for once, because every
  // one of the seven paths carries exactly one method; `check:named-gap-truth` moved 879 -> 886 in
  // this same commit. `workspace` (40) and `candidates` (47) are unchanged: these routes own no
  // environment route and serve no workspace lane, which is the evidence that only the registered
  // bucket moved.
  // 1137 -> 1138 (2026-09-14, M08.9): ONE handler, `GET /v1/hypervisor/work-projection` — the
  // policy-filtered Work read model over four published owner readers (sessions, goal runs, rooms,
  // automation runs) and the governance approval reader. It is a READ that writes nothing and owns
  // no environment route; `workspace` (40) and `candidates` (47) are unchanged, which is the
  // evidence that only the registered-handler bucket moved. The Systems projection route already
  // existed and gained identity policy in place, so it adds no handler. Moved in the SAME commit as
  // the route, together with `check:named-gap-truth` (878 -> 879 distinct paths).
  // 2026-09-17 (R-187, S4c-2): 12 handlers over the 11 deleted hosted-v2 OutcomeRoom routes went
  // with outcome_room_routes.rs and outcome_room_system_routes.rs (1165 → 1153); the workspace
  // population is unmoved. Before that, 2026-09-16 (R-178 S4a / R-179): 54 handlers over the 43
  // deleted `/v1/goal-orchestration/*` routes went with the room-hosted work-object,
  // participation, lease, terms and pairing modules (1219 → 1165).
  census.registered_route_handlers === 1136 /* 2026-09-22 (M06.10, R-228): 1130 → 1136, +6 to the REGISTERED bucket only — the jurisdiction-policy and compliance-audit-export plane: POST and GET handlers for packs, decisions and audit exports, six handlers on six distinct paths, so this census and the distinct-path census in verify-hypervisor-named-gap-truth.mjs move by the SAME amount this time. WORKSPACE HANDLERS (40) AND CANDIDATES (47) HELD: a jurisdiction pack declares obligations that compile into owners that already exist and is neither an environment-plane owner act nor an owner-resolvable environment surface; unresolved 0, unclassified 0. Moved in the SAME COMMIT as the routes. Before that, 2026-09-21 (M01.11, R-220): 1119 → 1130, +11 to the REGISTERED bucket only — canon's outward MCP Gateway API, eleven operations on nine distinct paths (the requirement listing and resolver; the profile list and create sharing `/v1/mcp/gateways`; get and patch sharing `/v1/mcp/gateways/:gateway_profile_id`; revoke, manifest, call, events and receipts). This census counts HANDLERS and the one in verify-hypervisor-named-gap-truth.mjs counts DISTINCT PATHS, so they move by 11 and 9 in the same commit — two paths carry two handlers each. WORKSPACE HANDLERS (40) AND CANDIDATES (47) HELD: a subject-scoped outward gateway profile is neither an environment-plane owner act nor an owner-resolvable environment surface; unresolved 0, unclassified 0. Moved in the SAME COMMIT as the routes. Before that, 2026-09-20 (M08.15, R-215): 1117 → 1119, +2 to the REGISTERED bucket only — the machine READ MODEL, two handlers on two new paths (`GET /v1/hypervisor/machines`, the inventory; `GET /v1/hypervisor/machines/:workload`, one workload's spine), both derived from the records on every read so that no client has to derive a head or a phase for itself. WORKSPACE HANDLERS (40) AND CANDIDATES (47) HELD: a read model over daemon-owned machine records is neither an environment-plane owner act nor an owner-resolvable environment surface; unresolved 0, unclassified 0. This census and the distinct-path census in verify-hypervisor-named-gap-truth.mjs move by the SAME amount this once (two paths, one handler each), and both pins moved in the same commit as the routes. Before that: 2026-09-18 (R-192, S5-1): 1154 → 1117, −37 net. The GoalRun family left the daemon on the owner's ruling that goal runs and outcome rooms are ioi.ai compositions over the thread orchestration primitives: the GoalRun routes, the GoalRun context family, the goal-profile contract registry and the IOI-Agent launch plane, less ONE handler added in the same slice — handle_work_lifecycle_record_append, the generic writer the work-lifecycle record chain needed once its only writer left with that plane. WORKSPACE HANDLERS (40) AND CANDIDATES (47) HELD: no environment-plane owner surface moved; unresolved 0, unclassified 0. This census counts HANDLERS and the one in verify-hypervisor-named-gap-truth.mjs counts DISTINCT PATHS, so the two move by different amounts in the same commit */ && census.workspace_route_handlers === 40
    && census.routes.length === 47 && census.unresolved.length === 0 && census.unclassified.length === 0
    && ownerRoute("GET", "/") && ownerRoute("GET", "/*preview_path")
    && aggregateRoutes.join(",") === "operability_routes::handle_operability_metrics,orchestration_routes::handle_placement_metrics"
    && policyContextRoutes.join(",") === [
      "cloud_job_routes::handle_cloud_job_execute",
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
