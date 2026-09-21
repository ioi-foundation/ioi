#!/usr/bin/env node
// check:mcp-non-tool-normalization — M01.10: canonical MCP non-tool primitive normalization, as a gate
// (docs/architecture/components/connectors-tools/contracts.md § MCP primitive normalization; ACC-1 clause 4
// and N5; register R-219).
//
// CANON. MCP is a TRANSPORT. Every exposed MCP primitive resolves to an EXISTING canonical owner with exact
// session, invocation and context bindings, produces the same admitted semantics as the native path, and
// fails TYPED-UNAVAILABLE rather than inventing truth when normalization is impossible. A resource URI is
// not a capability, a prompt is not a trusted instruction, an elicitation answer is not an approval, an MCP
// task is not a run identity or a receipt, and an App descriptor is not host or runtime truth.
//
// WHAT THIS RUNNER IS. Each clause is EXECUTED by one of this runner's own legs, by a floored gate that
// already proves it, or NAMED — a typed absence with an owner, or a scheduled leg with its prerequisite and
// ruling. The runner's own legs:
//   PURE    — the oracle in apps/hypervisor/scripts/lib/mcp-normalization.mjs over constructed decisions:
//             the closed vocabulary, the two constant grant members, a normalized decision that names no
//             record, a typed-unavailable one that names one, a status that disagrees with its decision, a
//             catalog entry advertising an unservable primitive, an App descriptor that derives a member.
//   SOURCE  — one envelope builder for the whole estate, validated against the registered contract before it
//             is served; the daemon's table equals the gate's; no emitter hand-rolls a second shape; the
//             stdio client answers rather than drops; canon's binding (pins).
//   CLIENT  — the REAL stdio client (crates/drivers) against two loopback stub MCP servers: one initiates a
//             request this client does not implement and must receive the typed refusal; one sends a
//             notification and must receive nothing while the session stays usable.
//   PLANE   — full mode, one isolated daemon: a thread, the fourteen non-tool routes answered and every
//             answer contract-valid; the App positive over a registration this runner admits through the
//             real ODK and Packages chain; native equivalence against the Packages route; an unregistered,
//             a recalled and a foreign-organization App refused BY NAME; the five N5 negatives; and the
//             record families unchanged by every read.
//
//   --drills           CI-bound, seconds: PURE, SOURCE, the binding and the verdict rules. No daemon.
//   --mutation         planted defects against the oracle — each must go red.
//   (default)          the full gate: the drills, CLIENT, PLANE, then the composed gates inside the
//                      isolated-egress harness. Exit 0 pass, 2 named failure, 1 fail.
//   --evidence <path>  also write the evidence there.

import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import { emitVerifierCensus } from "../apps/hypervisor/scripts/lib/verifier-census.mjs";
import { sanitizedVerifierBaseEnv, startIsolatedPlane } from "../apps/hypervisor/scripts/lib/isolated-daemon.mjs";
import { classifyLedger, probeIsolation, runIsolated } from "./lib/egress-harness.mjs";
import * as LIB from "../apps/hypervisor/scripts/lib/mcp-normalization.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, "..");
const APP_DIR = path.join(ROOT, "apps", "hypervisor");
const APP = "@ioi/hypervisor-app";
const FLOORS = path.join(APP_DIR, "verifier-floors.v1.json");
const LIB_PATH = path.join(APP_DIR, "scripts", "lib", "mcp-normalization.mjs");
const NORMALIZATION_ROUTES = path.join(ROOT, "crates", "node", "src", "bin", "hypervisor_daemon_routes", "mcp_normalization_routes.rs");
const LIFECYCLE_ROUTES = path.join(ROOT, "crates", "node", "src", "bin", "hypervisor_daemon_routes", "lifecycle_routes.rs");
const OPERABILITY_ROUTES = path.join(ROOT, "crates", "node", "src", "bin", "hypervisor_daemon_routes", "operability_routes.rs");
const DAEMON_MAIN = path.join(ROOT, "crates", "node", "src", "bin", "hypervisor-daemon.rs");
const STDIO_CLIENT = path.join(ROOT, "crates", "drivers", "src", "mcp", "transport.rs");
const CATALOG = path.join(ROOT, "crates", "services", "src", "agentic", "runtime", "kernel", "policy", "mcp_memory.rs");
const CANON = path.join(ROOT, "docs", "architecture", "components", "connectors-tools", "contracts.md");
const SCHEMA = path.join(ROOT, "docs", "architecture", "_meta", "schemas", "mcp-primitive-normalization-decision.v1.schema.json");

const argv = process.argv.slice(2);
const flag = (name) => argv.includes(name);
const flagValue = (name) => { const i = argv.indexOf(name); return i >= 0 ? argv[i + 1] : null; };
const MODE = flag("--mutation") ? "mutation" : flag("--drills") ? "drills" : "full";
const OWNER_Q = "owner question, R-219";

const gate = (script, floor, minutes) => ({ kind: "app", script, workspace: APP, floor, minutes });
const self = (name) => ({ kind: "self", script: `${name} (this runner)` });
const PURE = self("pure");
const SOURCE = self("source");
const CLIENT = self("client");
const PLANE = self("plane");
const TRANSPORT = gate("check:mcp-transport-normalization", "mcp-transport-normalization", 5);
const CONTRACTS = { kind: "root", script: "check:architecture-contracts", minutes: 5, undrilled: "the contract registry's own gate; its oracle is the generated-versus-authored golden fixture battery in ioi-types, which is a cargo test rather than a mutate: script" };

export const CLAUSES = [
  { n: 1, demand: "MCP is a transport and its answer is ONE registered contract: every normalization decision this estate emits — the thread-scoped routes, the outward gateway, the stdio client, the tool projection and connector discovery — carries the same eleven members under one schema, built in one place and validated against the registered contract BEFORE it is served", executed_by: [SOURCE, PLANE, CLIENT, CONTRACTS] },
  { n: 2, demand: "the primitive vocabulary is closed and the owner map is a table, not a chain of substring tests: an unrecognised path resolves to mcp.unknown rather than to the last branch, the daemon's table and this gate's agree row for row, and no primitive names a retired plane as its owner", executed_by: [PURE, SOURCE] },
  { n: 3, demand: "a refusal is a boundary, not a wall: every typed-unavailable decision names the canonical owner that would have to exist for the primitive to be served, carries a null backing ref, reports the lease as not minted, and grants neither authority nor receipt identity", executed_by: [PURE, PLANE] },
  { n: 4, demand: "the App primitive NORMALIZES: an MCP App resolves to an admitted extension_application registration, and the descriptor is a projection of that registration — its route, class, origin, creation method, effect boundary, declared contract sets, placements and launch modes — bound to the exact installation revision", executed_by: [PLANE, PURE] },
  { n: 5, demand: "native equivalence: the App read over MCP and the same registration read over the Packages route are the same record, member for member; the MCP path derives nothing the native path does not carry and admits nothing the native path would refuse", executed_by: [PLANE] },
  { n: 6, demand: "private projection: an App this organization has not admitted, an App whose release was recalled, and another organization's registration are each REFUSED BY NAME rather than described, and the refusal is the same registered decision", executed_by: [PLANE] },
  { n: 7, demand: "N5 — a resource URI cannot grant access: every resource route refuses typed-unavailable, names the owner that would serve it, mints no lease and produces no view", executed_by: [PLANE, PURE], absence: { what: `the resource POSITIVE normalization: ${LIB.ABSENCE_OWNERS["mcp.resource"]}`, owner: `the ioi.ai orchestration application's ContextLease (R-192, R-202) · ArtifactRef's producer (R-205) · MemoryProjection's contract (${OWNER_Q})` } },
  { n: 8, demand: "N5 — a prompt cannot become trusted instruction: the prompt routes refuse typed-unavailable, and the runtime catalog does not advertise a prompt as an invocable workflow node or require an authority scope for it", executed_by: [PLANE, SOURCE, PURE], absence: { what: `the prompt POSITIVE normalization: ${LIB.ABSENCE_OWNERS["mcp.prompt"]}`, owner: `M04.3's SkillManifest and the tainted-import record family (${OWNER_Q})` } },
  { n: 9, demand: "N5 — elicitation cannot approve and an MCP task cannot become a run identity: both routes refuse typed-unavailable and neither answer carries a receipt ref, an approval or a run identity", executed_by: [PLANE, PURE], absence: { what: `the elicitation and task POSITIVE normalizations: ${LIB.ABSENCE_OWNERS["mcp.elicitation"]}; ${LIB.ABSENCE_OWNERS["mcp.task"]}`, owner: `M01's typed-user-input family and the HarnessInvocation family (${OWNER_Q})` } },
  { n: 10, demand: "N5 — an App cannot acquire host or runtime truth: the descriptor says in its own bytes that it grants no host mutation, no runtime ownership, no authority and no receipt identity, and reading it writes no record to any family", executed_by: [PLANE, PURE] },
  { n: 11, demand: "the client half: a server-initiated primitive this client does not implement is ANSWERED with the typed refusal rather than dropped, a notification carries no id and is dropped deliberately rather than answered, and the session stays usable after both", executed_by: [CLIENT, SOURCE] },
  { n: 12, demand: "the transport's own invariants hold beneath all of this: the protocol revision is pinned and negotiated, every externally reachable MCP route is classified, the canonical route set is complete, and a tool arriving over MCP normalizes to the same RuntimeToolContract the native path resolves", executed_by: [TRANSPORT], absence: { what: "the outward Hypervisor MCP Gateway profile: both gateway routes still refuse typed-unavailable and no gateway profile schema is registered, so 'a tool arriving over MCP' is proven for the thread-scoped mount and NAMED for the outward gateway", owner: "M01.11 (check:hypervisor-mcp-gateway-profile) — ACC-1 clause 8 and N6" } },
];

// ---- infrastructure ----------------------------------------------------------------------------------------
const results = [];
const evidence = { schema: "ioi.mcp-non-tool-normalization-evidence.v1", mode: MODE, started_at: new Date().toISOString(), drills: [], pure: null, source: null, client: null, plane: null, clauses: [], verdict: null, mutation: null };
let sink = results;
function ok(name, cond, detail) {
  const row = { name, pass: !!cond, detail: detail == null ? "" : String(detail) };
  sink.push(row);
  if (sink === results) { evidence.drills.push({ ...row, at: new Date().toISOString() }); console.log(`${row.pass ? "PASS" : "FAIL"}  ${name}${row.detail ? ` — ${row.detail.slice(0, 220)}` : ""}`); }
  return row.pass;
}
function blocked(reason) { console.error(`BLOCKED: ${reason}`); writeEvidence(); process.exit(2); }
function writeEvidence() {
  evidence.finished_at = new Date().toISOString();
  evidence.summary = { passed: results.filter((r) => r.pass).length, total: results.length };
  const dir = path.join(ROOT, ".artifacts", "mvp-finish-line");
  fs.mkdirSync(dir, { recursive: true });
  const file = path.join(dir, `mcp-non-tool-normalization-${MODE}-${evidence.started_at.replace(/[:.]/g, "-")}.json`);
  fs.writeFileSync(file, `${JSON.stringify(evidence, null, 2)}\n`);
  const extra = flagValue("--evidence");
  if (extra) { fs.mkdirSync(path.dirname(path.resolve(ROOT, extra)), { recursive: true }); fs.writeFileSync(path.resolve(ROOT, extra), `${JSON.stringify(evidence, null, 2)}\n`); }
  return file;
}
const readText = (p) => fs.readFileSync(p, "utf8");
const readJson = (p) => JSON.parse(fs.readFileSync(p, "utf8"));
const sha256 = (s) => `sha256:${crypto.createHash("sha256").update(s).digest("hex")}`;
const REF = /^[a-z][a-z0-9+.-]*:\/\//u;

/** A decision the oracle should accept, built member by member so a drill can spoil exactly one. */
function decision(over = {}) {
  return {
    schema_version: LIB.DECISION_SCHEMA_VERSION,
    status: "typed_unavailable",
    primitive: "mcp.resource",
    canonical_owner: LIB.OWNERS_BY_PRIMITIVE["mcp.resource"],
    canonical_backing_ref: null,
    normalization_decision: "typed_unavailable",
    authority_granted: false,
    receipt_identity_granted: false,
    source_protocol_version: "2025-06-18",
    policy_lease_posture: "not_minted",
    reason: "no admitted canonical owner",
    ...over,
  };
}
const normalized = (over = {}) => decision({
  status: "normalized",
  normalization_decision: "normalized",
  primitive: "mcp.app",
  canonical_owner: LIB.OWNERS_BY_PRIMITIVE["mcp.app"],
  canonical_backing_ref: "surface://extensions/demo",
  policy_lease_posture: "not_applicable",
  reason: "resolved to an admitted registration",
  ...over,
});

// ---- PURE: the oracle over constructed decisions -------------------------------------------------------------
export function pureFindings(lib) {
  const f = [];
  const clean = (what, findings) => { if (findings.length) f.push(`${what}_rejected_a_clean_case:${findings.slice(0, 2).join("|")}`); };
  const dirty = (what, findings, needle) => {
    if (!findings.length) f.push(`${what}_accepted`);
    else if (needle && !findings.some((x) => x.includes(needle))) f.push(`${what}_wrong_finding:${findings[0]}`);
  };
  // 1. the two clean shapes are accepted
  clean("typed_unavailable", lib.decisionFindings(decision()));
  clean("normalized", lib.decisionFindings(normalized()));
  // 2. the two constants. Neither branch may grant.
  dirty("a typed-unavailable decision granting authority", lib.decisionFindings(decision({ authority_granted: true })), "authority_granted");
  dirty("a normalized decision granting authority", lib.decisionFindings(normalized({ authority_granted: true })), "authority_granted");
  dirty("a typed-unavailable decision granting receipt identity", lib.decisionFindings(decision({ receipt_identity_granted: true })), "receipt_identity_granted");
  dirty("a normalized decision granting receipt identity", lib.decisionFindings(normalized({ receipt_identity_granted: true })), "receipt_identity_granted");
  // 3. a normalization with no record behind it is the invented truth the unit refuses
  dirty("a normalized decision naming no record", lib.decisionFindings(normalized({ canonical_backing_ref: null })), "no admitted backing record");
  dirty("a normalized decision naming a bare string", lib.decisionFindings(normalized({ canonical_backing_ref: "demo" })), "no admitted backing record");
  dirty("a typed-unavailable decision naming a record", lib.decisionFindings(decision({ canonical_backing_ref: "surface://extensions/demo" })), "carries a backing ref");
  dirty("a typed-unavailable decision reporting a minted lease", lib.decisionFindings(decision({ policy_lease_posture: "minted" })), "lease posture");
  dirty("a typed-unavailable decision carrying receipts", lib.decisionFindings(decision({ receipt_refs: ["receipt://x/1"] })), "carries receipts");
  // 4. the closed vocabulary and the status agreement
  dirty("a primitive outside the vocabulary", lib.decisionFindings(decision({ primitive: "mcp.telepathy" })), "closed primitive vocabulary");
  dirty("a status that disagrees with its decision", lib.decisionFindings(decision({ status: "normalized" })), "disagrees");
  dirty("a decision that is neither normalized nor typed-unavailable", lib.decisionFindings(decision({ status: "RuntimeToolContract", normalization_decision: "RuntimeToolContract" })), "not a status");
  dirty("a decision naming no owner", lib.decisionFindings(decision({ canonical_owner: "" })), "names no canonical owner");
  dirty("a decision naming an owner in no table", lib.decisionFindings(decision({ canonical_owner: "WhateverPlane" })), "in no table");
  for (const member of lib.REQUIRED_DECISION_MEMBERS) {
    const without = decision();
    delete without[member];
    dirty(`a decision missing ${member}`, lib.decisionFindings(without), member);
  }
  // 5. the route table is closed
  for (const [segment, primitive] of lib.ROUTE_PRIMITIVES) {
    if (lib.classifyRoute(`/v1/threads/t${segment}/x`) !== primitive) f.push(`route_table_misses:${segment}`);
  }
  if (lib.classifyRoute("/v1/threads/t/mcp/telepathy") !== "mcp.unknown") f.push("route_table_guesses_an_unknown_path");
  if (lib.classifyClientMethod("sampling/createMessage") !== "mcp.sampling") f.push("client_method_table_misses_sampling");
  if (lib.classifyClientMethod("notifications/message") !== "mcp.notification") f.push("client_method_table_misses_notifications");
  if (lib.classifyClientMethod("telepathy/invoke") !== "mcp.unknown") f.push("client_method_table_guesses_an_unknown_method");
  // 6. the client's refusal shape
  const refusal = (over = {}) => ({ jsonrpc: "2.0", id: 7, error: { code: lib.TYPED_UNAVAILABLE_CODE, message: "typed unavailable", data: decision({ primitive: "mcp.sampling", canonical_owner: lib.OWNERS_BY_PRIMITIVE["mcp.sampling"] }) }, ...over });
  clean("the client refusal", lib.refusalFindings(refusal(), { method: "sampling/createMessage" }));
  dirty("silence from the client", lib.refusalFindings(null), "answered nothing");
  dirty("a client refusal with a result", lib.refusalFindings(refusal({ result: {} })), "carries a result");
  dirty("a client refusal answering no id", lib.refusalFindings(refusal({ id: null })), "answers no request id");
  dirty("a client refusal with the wrong code", lib.refusalFindings({ jsonrpc: "2.0", id: 7, error: { code: -32601, message: "x", data: decision({ primitive: "mcp.sampling", canonical_owner: lib.OWNERS_BY_PRIMITIVE["mcp.sampling"] }) } }), "typed-unavailable");
  dirty("a client refusal classifying the method as a neighbour", lib.refusalFindings(refusal(), { method: "roots/list" }), "classifies");
  // 7. the catalog fence
  const entry = (over = {}) => ({ invocable: false, workflow_node_type: null, workflow_node_id: null, authority_scope_requirements: [], normalization: decision({ primitive: "mcp.resource" }), ...over });
  clean("a fenced catalog entry", lib.catalogEntryFindings(entry(), "mcp.resource"));
  dirty("a catalog entry requiring an ungrantable scope", lib.catalogEntryFindings(entry({ authority_scope_requirements: ["scope:mcp.resource.read"] }), "mcp.resource"), "no owner normalizes");
  dirty("a catalog entry advertising a workflow node", lib.catalogEntryFindings(entry({ workflow_node_type: "McpResourceNode" }), "mcp.resource"), "no executor serves");
  dirty("a catalog entry advertising a workflow node id", lib.catalogEntryFindings(entry({ workflow_node_id: "runtime.mcp-resource.x" }), "mcp.resource"), "workflow node id");
  dirty("a catalog entry that does not declare itself non-invocable", lib.catalogEntryFindings(entry({ invocable: true }), "mcp.resource"), "non-invocable");
  dirty("a catalog entry claiming a normalization", lib.catalogEntryFindings(entry({ normalization: normalized({ primitive: "mcp.resource", canonical_owner: lib.OWNERS_BY_PRIMITIVE["mcp.resource"] }) }), "mcp.resource"), "claims a normalization");
  // a tool entry is normalizable, so it keeps its scope and its node type
  clean("a tool catalog entry", lib.catalogEntryFindings({ invocable: true, workflow_node_type: "McpToolNode", workflow_node_id: "runtime.mcp-tool.x", authority_scope_requirements: ["scope:mcp.invoke"] }, "mcp.tool"));
  // 8. the App descriptor projects and derives nothing
  const registration = { surface_ref: "surface://extensions/demo", display_name: "Demo", canonical_route: "/__ioi/extensions/demo", surface_class: "extension_application", surface_origin: "organization", surface_creation_method: "developer_kit_generated", effect_boundary: "propose_only", declared_object_contract_refs: ["object-model://demo"], declared_action_contract_refs: ["action://demo/start"], supported_placements: ["applications_catalog"], launch_modes: ["direct"] };
  const grants = { host_mutation: false, runtime_ownership: false, authority: false, receipt_identity: false };
  const descriptor = { app_id: "demo", surface_ref: registration.surface_ref, ...registration, grants };
  clean("the App descriptor", lib.appDescriptorFindings(descriptor, registration));
  for (const member of lib.APP_PROJECTED_MEMBERS) {
    dirty(`an App descriptor deriving ${member}`, lib.appDescriptorFindings({ ...descriptor, [member]: "derived" }, registration), member);
  }
  dirty("an App descriptor bound to another surface", lib.appDescriptorFindings({ ...descriptor, surface_ref: "surface://extensions/other" }, registration), "different surface");
  for (const member of lib.APP_GRANT_MEMBERS) {
    dirty(`an App descriptor granting ${member}`, lib.appDescriptorFindings({ ...descriptor, grants: { ...grants, [member]: true } }, registration), member);
  }
  dirty("an App descriptor that says nothing about grants", lib.appDescriptorFindings({ ...descriptor, grants: null }, registration), "does not say");
  return f;
}

// ---- SOURCE: one envelope, one table, no second shape ---------------------------------------------------------
export function sourceFindings(s) {
  const f = [];
  const { normalizationRoutes, lifecycle, operability, daemonMain, stdio, catalog, canon, schema, lib } = s;
  // 1. ONE BUILDER, and it validates before it serves.
  if (!/pub\(crate\) fn normalization_decision\(/u.test(normalizationRoutes)) f.push("pin_no_single_envelope_builder");
  if (!normalizationRoutes.includes("validate_architecture_contract(")) f.push("pin_builder_does_not_validate");
  if (!normalizationRoutes.includes(lib.DECISION_CONTRACT_ID)) f.push("pin_builder_validates_against_another_contract");
  if (!/mcp_normalization_decision_invalid/u.test(normalizationRoutes)) f.push("pin_invalid_decision_is_not_a_typed_failure");
  // 2. NO SECOND SHAPE. The three former hand-rolled emitters now delegate.
  if (/"schema_version":\s*"ioi\.runtime\.mcp-normalization-decision\.v1"/u.test(lifecycle)) f.push("pin_lifecycle_still_hand_rolls_the_envelope");
  if (/"schema_version":\s*"ioi\.runtime\.mcp-normalization-decision\.v1"/u.test(operability)) f.push("pin_gateway_still_hand_rolls_the_envelope");
  if (!/mcp_normalization_routes::typed_unavailable\(/u.test(lifecycle)) f.push("pin_thread_routes_do_not_delegate");
  if (!/mcp_normalization_routes::gateway_typed_unavailable\(/u.test(operability)) f.push("pin_gateway_does_not_delegate");
  // The two richer projections carry the registered decision beside their own members rather than instead.
  for (const [what, needle] of [["the tool projection", '"normalization": normalization'], ["connector discovery", '"normalization": candidate_normalization']]) {
    if (!lifecycle.includes(needle)) f.push(`pin_${what.replace(/\s+/gu, "_")}_does_not_carry_the_decision`);
  }
  if (/"normalization_decision":\s*"RuntimeToolContract"/u.test(lifecycle)) f.push("pin_normalization_decision_still_carries_an_owner_name");
  // 3. THE TABLE. Closed, and the same on both sides.
  f.push(...lib.tableParityFindings(normalizationRoutes));
  if (!/\("mcp\.unknown", "none"\)/u.test(normalizationRoutes)) f.push("pin_unknown_path_falls_through_to_a_neighbour");
  if (/\} else if \(path\.contains|fn mcp_unavailable_classification/u.test(lifecycle)) f.push("pin_the_substring_chain_survives");
  // 4. THE APP POSITIVE is a projection of an admitted registration, and it grants nothing.
  if (!/registered_extension_surfaces\(/u.test(normalizationRoutes)) f.push("pin_app_positive_does_not_read_the_admitted_registration");
  for (const member of lib.APP_GRANT_MEMBERS) if (!new RegExp(`"${member}":\\s*false`, "u").test(normalizationRoutes)) f.push(`pin_app_descriptor_is_silent_on_${member}`);
  if (!/extension_application_registration_absent/u.test(normalizationRoutes)) f.push("pin_an_unadmitted_app_is_not_refused_by_name");
  if (!/mcp_normalization_routes::handle_mcp_apps_search/u.test(daemonMain) || !/mcp_normalization_routes::handle_mcp_app_descriptor/u.test(daemonMain)) f.push("pin_the_app_routes_are_not_mounted_on_the_positive");
  // 5. THE CLIENT ANSWERS. Silence was the defect. These pins read CODE only: a negative pin that read the
  //    comment explaining the removal would go red precisely when the defect was fixed and documented.
  const clientCode = lib.codeOnly(stdio);
  if (!/fn normalization_refusal\(/u.test(clientCode)) f.push("pin_client_has_no_refusal");
  if (!new RegExp(`MCP_TYPED_UNAVAILABLE_CODE: i64 = ${lib.TYPED_UNAVAILABLE_CODE}`, "u").test(clientCode)) f.push("pin_client_refusal_code_drift");
  if (!/"jsonrpc": "2\.0"[\s\S]{0,200}"error"/u.test(clientCode)) f.push("pin_client_refusal_is_not_json_rpc");
  if (/Auto-acking/u.test(clientCode)) f.push("pin_client_still_auto_acks");
  if (/listChanged/u.test(clientCode)) f.push("pin_client_declares_a_capability_it_does_not_serve");
  if (!/"capabilities": \{\}/u.test(clientCode)) f.push("pin_client_initialize_does_not_declare_an_empty_capability_set");
  // 6. THE CATALOG does not advertise what nothing normalizes.
  for (const scope of ["scope:mcp.resource.read", "scope:mcp.prompt.read"]) {
    if (catalog.includes(`"${scope}"`)) f.push(`pin_catalog_requires_the_ungrantable_scope:${scope}`);
  }
  for (const node of ["McpResourceNode", "McpPromptNode"]) {
    if (new RegExp(`"workflow_node_type":\\s*"${node}"`, "u").test(catalog)) f.push(`pin_catalog_advertises_an_unserved_node_type:${node}`);
  }
  if (!/"invocable":\s*false/u.test(catalog)) f.push("pin_catalog_entries_do_not_declare_themselves_non_invocable");
  // 7. CANON and the registered contract say the same thing the code does.
  if (!/MCP primitive normalization/u.test(canon)) f.push("pin_canon_section_absent");
  if (!canon.includes(lib.DECISION_CONTRACT_ID)) f.push("pin_canon_does_not_name_the_registered_contract");
  const enumerated = JSON.parse(schema).properties?.primitive?.enum ?? [];
  if (JSON.stringify([...enumerated].sort()) !== JSON.stringify([...lib.PRIMITIVES].sort())) f.push(`pin_schema_vocabulary_drift:${enumerated.length}≠${lib.PRIMITIVES.length}`);
  return f;
}

function sourceInputs() {
  return {
    normalizationRoutes: readText(NORMALIZATION_ROUTES),
    lifecycle: readText(LIFECYCLE_ROUTES),
    operability: readText(OPERABILITY_ROUTES),
    daemonMain: readText(DAEMON_MAIN),
    stdio: readText(STDIO_CLIENT),
    catalog: readText(CATALOG),
    canon: readText(CANON),
    schema: readText(SCHEMA),
    lib: LIB,
  };
}

// ---- the binding: floors, scripts, CI, the clause table ---------------------------------------------------------
export function bindingFindings({ rootPkg, appPkg, floors, ci }) {
  const f = [];
  if (!rootPkg.scripts?.["check:mcp-non-tool-normalization"]) f.push("root_script_missing");
  if (!rootPkg.scripts?.["mutate:mcp-non-tool-normalization"]) f.push("root_mutation_script_missing");
  if (!appPkg.scripts?.["check:mcp-transport-normalization"]) f.push("transport_script_missing");
  const rows = floors.verifiers ?? floors.floors ?? [];
  const named = (id) => rows.find((r) => r.verifier === id || r.id === id);
  for (const id of ["mcp-non-tool-normalization", "mcp-transport-normalization"]) {
    const row = named(id);
    if (!row) f.push(`floor_row_missing:${id}`);
    else if (!(Number.isInteger(row.runtime_assertions) && row.runtime_assertions > 0)) f.push(`floor_row_without_a_floor:${id}`);
    else if (!(typeof row.assertion_names_sha256 === "string" && /^[0-9a-f]{64}$/u.test(row.assertion_names_sha256))) f.push(`floor_row_without_a_name_digest:${id}`);
    else if (!(typeof row.note === "string" && row.note.length > 200)) f.push(`floor_row_without_a_note_saying_what_it_counts:${id}`);
  }
  if (!/check:mcp-non-tool-normalization/u.test(ci)) f.push("gate_not_ci_bound");
  if (!/check:mcp-transport-normalization/u.test(ci)) f.push("transport_gate_not_ci_bound");
  const seen = new Set();
  for (const c of CLAUSES) {
    seen.add(c.n);
    if (!(typeof c.demand === "string" && c.demand.length > 40)) f.push(`clause_${c.n}_demand_too_thin`);
    if (!(c.executed_by?.length) && !c.absence) f.push(`clause_${c.n}_neither_executed_nor_named`);
    for (const g of c.executed_by ?? []) {
      if (g.kind === "app") {
        if (!appPkg.scripts?.[g.script]) f.push(`clause_${c.n}_binds_missing_script: ${g.script}`);
        if (!g.floor) f.push(`clause_${c.n}_binds_unfloored_gate: ${g.script}`);
        else if (!named(g.floor)) f.push(`clause_${c.n}_binds_absent_floor_row: ${g.floor}`);
      } else if (g.kind === "root") {
        if (!rootPkg.scripts?.[g.script]) f.push(`clause_${c.n}_binds_missing_script: ${g.script}`);
        if (!rootPkg.scripts?.[g.script.replace(/^check:/u, "mutate:")] && !(typeof g.undrilled === "string" && g.undrilled.length > 20)) f.push(`clause_${c.n}_binds_undrilled_root_script: ${g.script}`);
      } else if (g.kind !== "self") f.push(`clause_${c.n}_unknown_gate_kind: ${g.kind}`);
    }
    if (c.absence && !(typeof c.absence.owner === "string" && c.absence.owner.trim().length > 0 && typeof c.absence.what === "string" && c.absence.what.length > 20)) f.push(`clause_${c.n}_absence_without_owner`);
    if (c.scheduled && !(typeof c.scheduled.prerequisite === "string" && c.scheduled.prerequisite.length > 20 && typeof c.scheduled.ruling === "string" && /R-\d+/u.test(c.scheduled.ruling))) f.push(`clause_${c.n}_scheduled_without_prerequisite_or_ruling`);
  }
  for (let n = 1; n <= 12; n += 1) if (!seen.has(n)) f.push(`clause_missing: ${n}`);
  return f;
}

export function verdict(rows) {
  const failures = [];
  const absences = [];
  const seen = new Set();
  for (const r of rows) {
    if (!Number.isInteger(r.n) || r.n < 1 || r.n > 12) { failures.push(`row_out_of_range:${r.n}`); continue; }
    if (seen.has(r.n)) failures.push(`row_duplicated:${r.n}`);
    seen.add(r.n);
    for (const g of r.executed ?? []) {
      if (g.status !== 0) failures.push(`clause_${r.n}_red: ${g.script} exit ${g.status}`);
      else if (!g.evidence || !g.evidence_sha256) failures.push(`clause_${r.n}_fabricated: ${g.script} reports success without evidence`);
      if (g.ledger && g.ledger.reach > 0) failures.push(`clause_${r.n}_undeclared_egress: ${g.script} reached ${g.ledger.reach} non-loopback destination(s)`);
      if (g.floor_expected != null && g.executed_assertions != null && g.executed_assertions < g.floor_expected) failures.push(`clause_${r.n}_below_floor: ${g.script} ${g.executed_assertions} < ${g.floor_expected}`);
    }
    if (r.absence) { if (!(r.absence.owner && r.absence.what)) failures.push(`clause_${r.n}_absence_without_owner`); else absences.push({ n: r.n, ...r.absence }); }
    if (r.scheduled) { if (!(r.scheduled.prerequisite && r.scheduled.ruling)) failures.push(`clause_${r.n}_scheduled_without_prerequisite_or_ruling`); else absences.push({ n: r.n, what: `SCHEDULED-OUTSTANDING: ${r.scheduled.what}`, owner: `prerequisite: ${r.scheduled.prerequisite} · ${r.scheduled.ruling}` }); }
    if (r.not_executed) absences.push({ n: r.n, what: `not executed in this run: ${r.not_executed}`, owner: "this runner (on demand)" });
  }
  for (let n = 1; n <= 12; n += 1) if (!seen.has(n)) failures.push(`row_missing:${n}`);
  return { kind: failures.length ? "fail" : absences.length ? "named_failure" : "pass", failures, absences };
}

// ---- drills -----------------------------------------------------------------------------------------------------
async function drills() {
  const pure = pureFindings(LIB);
  evidence.pure = { findings: pure };
  ok("PURE — the oracle refuses every constructed decision that claims more than it resolved, and accepts the two clean shapes", pure.length === 0, pure.slice(0, 4).join(" ; "));
  const src = sourceFindings(sourceInputs());
  evidence.source = { findings: src };
  ok("SOURCE — one contract-validated envelope builder, no second hand-rolled shape, a closed table equal on both sides, the App positive over an admitted registration, a client that answers, a fenced catalog and canon that says so", src.length === 0, src.slice(0, 4).join(" ; "));
  const binding = bindingFindings({
    rootPkg: readJson(path.join(ROOT, "package.json")),
    appPkg: readJson(path.join(APP_DIR, "package.json")),
    floors: readJson(FLOORS),
    ci: fs.readdirSync(path.join(ROOT, ".github", "workflows")).map((file) => readText(path.join(ROOT, ".github", "workflows", file))).join("\n"),
  });
  ok("BINDING — both gates are floored and CI-bound, every clause is executed or named with an owner, and the twelve clauses are present", binding.length === 0, binding.slice(0, 4).join(" ; "));
  const v = verdict([{ n: 1, executed: [{ script: "x", status: 0, evidence: {}, evidence_sha256: "s" }] }]);
  ok("VERDICT — a table missing eleven of its twelve rows is a FAIL, not a pass", v.kind === "fail" && v.failures.some((x) => x === "row_missing:12"), v.failures.slice(0, 2).join(" ; "));
  const all = Object.fromEntries([...Array(12)].map((_, i) => [i, null]));
  const full = verdict([...Array(12)].map((_, i) => ({ n: i + 1, executed: [{ script: "x", status: 0, evidence: {}, evidence_sha256: "s" }] })));
  ok("VERDICT — twelve green rows with no absence is a PASS", full.kind === "pass" && Object.keys(all).length === 12, full.failures.slice(0, 2).join(" ; "));
  const named = verdict([...Array(12)].map((_, i) => ({ n: i + 1, executed: [{ script: "x", status: 0, evidence: {}, evidence_sha256: "s" }], absence: i === 6 ? { what: "a named absence long enough to be real", owner: "someone" } : null })));
  ok("VERDICT — one named absence is a NAMED FAILURE, never a pass", named.kind === "named_failure" && named.absences.length === 1, named.kind);
  const unevidenced = verdict([...Array(12)].map((_, i) => ({ n: i + 1, executed: [{ script: "x", status: 0 }] })));
  ok("VERDICT — a gate that reports success without evidence is fabricated, not green", unevidenced.kind === "fail" && unevidenced.failures.every((x) => x.includes("fabricated")), unevidenced.failures[0]);
  const reached = verdict([...Array(12)].map((_, i) => ({ n: i + 1, executed: [{ script: "x", status: 0, evidence: {}, evidence_sha256: "s", ledger: { attempts: 1, loopback: 0, reach: 1 } }] })));
  ok("VERDICT — a gate that reached a non-loopback destination fails, whatever it returned", reached.kind === "fail" && reached.failures.every((x) => x.includes("undeclared_egress")), reached.failures[0]);
  const belowFloor = verdict([...Array(12)].map((_, i) => ({ n: i + 1, executed: [{ script: "x", status: 0, evidence: {}, evidence_sha256: "s", floor_expected: 9, executed_assertions: 2 }] })));
  ok("VERDICT — a gate below its floor fails even at exit 0", belowFloor.kind === "fail" && belowFloor.failures.every((x) => x.includes("below_floor")), belowFloor.failures[0]);
}

// ---- mutation ------------------------------------------------------------------------------------------------------
async function mutation() {
  const original = readText(LIB_PATH);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "mcp-normalization-mutation-"));
  let planted = 0;
  let caught = 0;
  const mutate = async (what, transform, expect) => {
    planted += 1;
    const file = path.join(dir, `m${planted}.mjs`);
    const text = transform(original);
    if (text === original) { console.log(`FAIL  mutation ${planted} (${what}) — the planted defect changed nothing`); return; }
    fs.writeFileSync(file, text);
    let findings = [];
    try { findings = expect(await import(pathToFileURL(file).href)); } catch (error) { findings = [`threw:${error.message}`]; }
    const red = findings.length > 0;
    if (red) caught += 1;
    console.log(`${red ? "  ok  " : " FAIL "} mutation ${planted} — ${what}${red ? "" : " SURVIVED"}`);
  };
  const pure = (mod) => pureFindings(mod);
  // The table oracle cannot be drilled against the real tree: the real tree SATISFIES it, so a mutant that
  // deletes the check produces the same empty result as the intact one. Each of these hands the module a
  // DELIBERATELY BROKEN table and asks whether the module still notices; a mutant that stopped checking
  // returns nothing and is caught by that silence.
  const tableOracle = (mod) => {
    const f = [];
    const base = sourceInputs().normalizationRoutes;
    const before = (text) => base.replace("#[cfg(test)]", `${text}\n#[cfg(test)]`);
    const renamedRow = base.replace('"/apps",', '"/applications",');
    if (!mod.tableParityFindings(renamedRow).some((x) => x.includes("/apps"))) f.push("a dropped table row was accepted");
    const namesAGoalRun = before('const RETIRED_OWNER: &str = "GoalRunProfile";');
    if (!mod.tableParityFindings(namesAGoalRun).some((x) => x.includes("GoalRun"))) f.push("a retired plane named as a canonical owner was accepted");
    const losesAnOwner = base.replace('"typed-user-input-request"', '"whatever-comes-along"');
    if (!mod.tableParityFindings(losesAnOwner).some((x) => x.includes("typed-user-input-request"))) f.push("a primitive whose owner is no longer named was accepted");
    return f;
  };
  // the two constants
  await mutate("the oracle stops refusing an authority grant", (t) => t.replace('if (decision.authority_granted !== false) {', "if (false) {"), pure);
  await mutate("the oracle stops refusing a receipt-identity grant", (t) => t.replace('if (decision.receipt_identity_granted !== false) {', "if (false) {"), pure);
  // the backing record
  await mutate("a normalized decision may name no record", (t) => t.replace('if (typeof decision.canonical_backing_ref !== "string" || !/^[a-z][a-z0-9+.-]*:\\/\\//.test(decision.canonical_backing_ref)) {', "if (false) {"), pure);
  await mutate("a typed-unavailable decision may name a record", (t) => t.replace("if (decision.canonical_backing_ref !== null) {", "if (false) {"), pure);
  await mutate("a typed-unavailable decision may report a minted lease", (t) => t.replace('if (decision.policy_lease_posture !== "not_minted") {', "if (false) {"), pure);
  await mutate("a typed-unavailable decision may carry receipts", (t) => t.replace("if (Array.isArray(decision.receipt_refs) && decision.receipt_refs.length > 0) {", "if (false) {"), pure);
  // the vocabulary and the agreement
  await mutate("the primitive vocabulary opens", (t) => t.replace("if (!PRIMITIVES.includes(decision.primitive)) {", "if (false) {"), pure);
  await mutate("status may disagree with the decision", (t) => t.replace("if (decision.status !== status) {", "if (false) {"), pure);
  await mutate("a decision may name no owner", (t) => t.replace('if (typeof decision.canonical_owner !== "string" || decision.canonical_owner.length === 0) {', "if (false) {"), pure);
  await mutate("a required member may be absent", (t) => t.replace("if (!(member in decision)) findings.push(`${where}: the member ${member} is absent`);", ""), pure);
  // the tables
  await mutate("an unknown route is guessed into the serve primitive", (t) => t.replace('return "mcp.unknown";\n}\n\nexport function classifyClientMethod', 'return "mcp.serve";\n}\n\nexport function classifyClientMethod'), pure);
  await mutate("an unknown client method is guessed into sampling", (t) => t.replace('if (String(method).startsWith("notifications/")) return "mcp.notification";\n  return "mcp.unknown";', 'if (String(method).startsWith("notifications/")) return "mcp.notification";\n  return "mcp.sampling";'), pure);
  // the client refusal
  await mutate("the client may answer with silence", (t) => t.replace('if (!response || typeof response !== "object") return ["the client answered nothing"];', 'if (!response || typeof response !== "object") return [];'), pure);
  await mutate("the client refusal code may drift", (t) => t.replace("if (error.code !== TYPED_UNAVAILABLE_CODE) {", "if (false) {"), pure);
  await mutate("the client refusal may carry a result", (t) => t.replace('if (response.result !== undefined) findings.push("the refusal carries a result");', ""), pure);
  // the catalog fence
  await mutate("the catalog may require an ungrantable scope", (t) => t.replace("} else if (!normalizable && scopes.length > 0) {", "} else if (false) {"), pure);
  await mutate("the catalog may advertise an unserved workflow node", (t) => t.replace("if (entry.workflow_node_type !== null) {", "if (false) {"), pure);
  await mutate("the catalog need not declare itself non-invocable", (t) => t.replace("if (entry.invocable !== false) {", "if (false) {"), pure);
  // the App projection
  await mutate("the App descriptor may derive a member", (t) => t.replace("if (projected !== admitted) {", "if (false) {"), pure);
  await mutate("the App descriptor may grant", (t) => t.replace("if (grants[member] !== false) findings.push(`the App descriptor grants ${member}`);", ""), pure);
  await mutate("the App descriptor may be bound to another surface", (t) => t.replace("if (descriptor.surface_ref !== registration.surface_ref) {", "if (false) {"), pure);
  // the source parity oracle, each against a deliberately broken table
  await mutate("the daemon's table may drop a row", (t) => t.replace("if (!row.test(table)) findings.push(`the daemon's table has no row mapping ${segment} to ${primitive}`);", ""), tableOracle);
  await mutate("the daemon may name a GoalRun as a canonical owner again (R-192)", (t) => t.replace("if (/GoalRun/.test(table)) {", "if (false) {"), tableOracle);
  await mutate("the daemon may stop naming a non-tool primitive's owner", (t) => t.replace("if (!table.includes(owner)) {", "if (false) {"), tableOracle);
  // and the comment stripper itself: a pin that reads prose fires when the defect is FIXED and written up
  await mutate("a source pin may read explanatory comments again", (t) => t.replace('.filter((line) => !/^\\s*\\/\\//u.test(line))', ".filter(() => true)"), (mod) => {
    const commentOnly = 'const OWNERS: &str = "x";\n// this table must never name a GoalRunProfile again\n';
    return mod.tableParityFindings(commentOnly).some((x) => x.includes("GoalRun")) ? ["a source pin fired on prose"] : [];
  });
  fs.rmSync(dir, { recursive: true, force: true });
  evidence.mutation = { planted, caught };
  console.log(`\n${caught}/${planted} planted defects caught`);
  return caught === planted && planted >= 24;
}

// ---- CLIENT: the real stdio client against two loopback stub MCP servers ------------------------------------------
function clientLeg() {
  const findings = [];
  const started = Date.now();
  const run = spawnSync("cargo", ["test", "-p", "ioi-drivers", "--lib", "mcp::transport", "--", "--nocapture"], {
    cwd: ROOT,
    encoding: "utf8",
    env: { ...process.env, RUST_BACKTRACE: "1" },
    maxBuffer: 64 * 1024 * 1024,
    timeout: 20 * 60 * 1000,
  });
  const out = `${run.stdout ?? ""}${run.stderr ?? ""}`;
  if (run.status !== 0) findings.push(`client_tests_red:${(out.match(/^test .*FAILED$/gmu) ?? []).slice(0, 3).join("|") || `exit ${run.status}`}`);
  const named = (name) => new RegExp(`test .*${name} \\.\\.\\. ok`, "u").test(out);
  for (const t of [
    "a_server_initiated_request_is_answered_with_the_typed_refusal",
    "a_server_notification_is_dropped_and_the_session_stays_usable",
    "every_server_initiated_refusal_is_the_registered_contract",
    "a_refusal_names_the_owner_that_would_serve_the_primitive",
  ]) if (!named(t)) findings.push(`client_test_did_not_run:${t}`);
  return { findings, seconds: Math.round((Date.now() - started) / 1000), tests: (out.match(/test result: ok\. (\d+) passed/u) ?? [])[1] ?? null };
}

// ---- PLANE: one isolated daemon ------------------------------------------------------------------------------------
async function planeLeg() {
  const findings = [];
  const f = (x) => findings.push(x);
  const started = Date.now();
  const daemonBinary = path.resolve(ROOT, process.env.IOI_HYPERVISOR_DAEMON_BINARY || "target/debug/hypervisor-daemon");
  if (!fs.existsSync(daemonBinary)) return { findings: ["daemon_binary_absent"], blocked: true };
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "mcp-normalization-plane-"));
  const baseEnv = sanitizedVerifierBaseEnv();
  let plane = null;
  const observed = { decisions: 0, contract_valid: 0 };
  try {
    plane = await startIsolatedPlane({ baseEnv, env: { IOI_HYPERVISOR_MODEL_UPSTREAM: "http://127.0.0.1:9/v1", IOI_HYPERVISOR_DAEMON_BINARY: daemonBinary }, dataDir, serve: false });
    if (!plane) return { findings: ["isolated_plane_did_not_start"], blocked: true };
    const DAEMON = plane.daemonUrl;
    const token = (() => {
      const logs = fs.readdirSync(dataDir).filter((x) => /^isolated-daemon.*\.log$/u.test(x)).sort().reverse();
      for (const log of logs) {
        const t = fs.readFileSync(path.join(dataDir, log), "utf8").match(/ioi_bootstrap_[a-f0-9]{64}/gu)?.at(-1);
        if (t) return t;
      }
      return null;
    })();
    let cookie = "";
    const jd = async (base, tail, init = {}) => {
      const r = await fetch(`${base}${tail}`, {
        ...init,
        redirect: "manual",
        headers: { ...(init.body ? { "content-type": "application/json" } : {}), ...(init.anonymous ? {} : cookie ? { cookie } : {}), ...(init.headers ?? {}) },
      }).catch((error) => ({ status: 0, text: async () => String(error) }));
      const text = await r.text().catch(() => "");
      let body = null;
      try { body = text ? JSON.parse(text) : {}; } catch { body = { raw: text.slice(0, 400) }; }
      return { status: r.status, body };
    };
    const boot = await jd(DAEMON, "/v1/hypervisor/auth/bootstrap", { method: "POST", body: JSON.stringify({ token, password: "mcp-normalization-pass-1", email: "mcp-normalization@ioi.local" }) });
    cookie = boot.body?.session_token ? `ioi_session=${boot.body.session_token}` : "";
    if (!cookie) f(`bootstrap:${boot.status}:${JSON.stringify(boot.body).slice(0, 160)}`);
    const OWNER = "org://local";

    // --- a thread to scope the MCP routes to
    const thread = await jd(DAEMON, "/v1/threads", { method: "POST", body: JSON.stringify({ title: "mcp normalization" }) });
    const threadId = thread.body?.thread?.id || thread.body?.id || thread.body?.thread_id;
    if (!threadId) { f(`thread_create:${thread.status}:${JSON.stringify(thread.body).slice(0, 200)}`); return { findings, seconds: Math.round((Date.now() - started) / 1000) }; }

    // The HTTP status is part of the answer and is NOT derivable from the decision: a primitive nobody
    // built is 501, and an App this organization never admitted is 404 — the same typed decision, two
    // different facts about the request, and conflating them would tell a caller to go build a resource
    // owner when what they actually did was name an App that is not there.
    const check = (what, answer, expectPrimitive, expectStatus, expectHttp) => {
      observed.decisions += 1;
      const d = answer.body;
      const bad = LIB.decisionFindings(d, { where: what });
      if (bad.length) f(`${what}:${bad.slice(0, 2).join("|")}`);
      else observed.contract_valid += 1;
      if (d?.primitive !== expectPrimitive) f(`${what}_primitive:${d?.primitive}≠${expectPrimitive}`);
      if (d?.normalization_decision !== expectStatus) f(`${what}_status:${d?.normalization_decision}≠${expectStatus}`);
      if (answer.status !== expectHttp) f(`${what}_http:${answer.status}≠${expectHttp}`);
      return d;
    };

    // --- N5: the four non-tool primitives with no owner refuse, typed, on every route
    const T = `/v1/threads/${encodeURIComponent(threadId)}/mcp`;
    const refusals = [
      ["resource_search", `${T}/resources/search`, "GET", "mcp.resource"],
      ["resource_get", `${T}/resources/r1`, "GET", "mcp.resource"],
      ["resource_read", `${T}/resources/r1/read`, "POST", "mcp.resource"],
      ["prompt_search", `${T}/prompts/search`, "GET", "mcp.prompt"],
      ["prompt_get", `${T}/prompts/p1`, "GET", "mcp.prompt"],
      ["prompt_import", `${T}/prompts/p1/imports`, "POST", "mcp.prompt"],
      ["elicitation_create", `${T}/elicitation-requests`, "POST", "mcp.elicitation"],
      ["elicitation_respond", `${T}/elicitation-requests/e1/responses`, "POST", "mcp.elicitation"],
      ["task_create", `${T}/external-task-bindings`, "POST", "mcp.task"],
      ["task_get", `${T}/external-task-bindings/b1`, "GET", "mcp.task"],
      ["task_cancel", `${T}/external-task-bindings/b1/cancel`, "POST", "mcp.task"],
      ["serve", `${T}/serve`, "POST", "mcp.serve"],
    ];
    for (const [what, tail, method, primitive] of refusals) {
      const answer = await jd(DAEMON, tail, method === "GET" ? {} : { method, body: "{}" });
      const d = check(what, answer, primitive, "typed_unavailable", 501);
      // N5, said exactly: the refusal grants nothing and produces nothing.
      if (d?.canonical_backing_ref !== null) f(`${what}_carries_a_backing_ref`);
      if (d?.receipt_refs?.length) f(`${what}_carries_a_receipt`);
      if (!d?.canonical_owner) f(`${what}_names_no_owner`);
    }
    // the outward gateway answers the SAME contract
    const gw = await jd(DAEMON, "/v1/hypervisor/mcp-gateway/tools");
    check("gateway_tools", gw, "mcp.gateway", "typed_unavailable", 501);

    // --- the App positive: an unadmitted App is refused BY NAME before anything is admitted
    const absent = await jd(DAEMON, `${T}/apps/nothing-here/descriptor`);
    const absentDecision = check("app_absent", absent, "mcp.app", "typed_unavailable", 404);
    if (absentDecision?.refusal_code !== "extension_application_registration_absent") f(`app_absent_refusal_code:${absentDecision?.refusal_code}`);
    const emptySearch = await jd(DAEMON, `${T}/apps/search`);
    if (emptySearch.body?.app_count !== 0) f(`app_search_before_admission:${emptySearch.body?.app_count}`);

    // --- admit ONE extension_application through the real ODK + Packages chain
    const NS = "mcp-normalization"; const ONT = "console"; const PKG = "mcp-app-under-test"; const INST = "primary";
    const SURFACE_REF = `surface://extensions/${PKG}`;
    const ont = await jd(DAEMON, "/v1/hypervisor/odk/domain-ontologies", { method: "POST", body: JSON.stringify({ domain: NS, owner_ref: OWNER, idempotency_key: "mnn-ont-1" }) });
    const ontRef = ont.body?.ontology?.ref || "";
    const version = await jd(DAEMON, "/v1/hypervisor/ontology-versions", { method: "POST", body: JSON.stringify({ owner_ref: OWNER, idempotency_key: "mnn-ver-1", namespace: NS, name: ONT, governing_scope_ref: `domain://${NS}/registry`, policy_hash: `sha256:${"1a".repeat(32)}`, entity_types: [{ term_id: `ontology://${NS}/${ONT}/term/app`, label: "app" }], valid_time: { starts_at: "2026-01-01T00:00:00Z", ends_at: null } }) });
    const revisionRef = version.body?.ontology_version?.ontology_id || "";
    const sd = await jd(DAEMON, "/v1/hypervisor/odk/surface-descriptors", { method: "POST", body: JSON.stringify({ owner_ref: OWNER, idempotency_key: "mnn-sd-1", schema_version: "ioi.ontology-surface-descriptor.v2", display_name: "MCP App under test", surface_ref: SURFACE_REF, composition_pattern: "domain_app", ontology_refs: [revisionRef], canonical_object_model_refs: [`object-model://${NS}/${ONT}/app`], data_recipe_refs: [], policy_bound_data_view_refs: [`view://${NS}/apps`], authority_requirement_refs: ["scope:extensions.read"], daemon_api_refs: ["api://v1/hypervisor/environments-summary"], receipt_obligations: [`receipt://${NS}/open`], conformance_profile_refs: [`profile://${NS}/v1`], connector_mapping_refs: [], ontology_projection_refs: [], allowed_action_refs: [`action://${NS}/open`], operator_contract_refs: [], mcp_contract_refs: [], generated_artifact_refs: [], does_not_assert: ["authority", "capability_lease_crossing", "runtime_truth", "semantic_truth", "permission_truth", "marketplace_truth"] }) });
    const sdRef = sd.body?.surface_descriptor?.surface_descriptor_id || "";
    const man = await jd(DAEMON, "/v1/hypervisor/odk/manifests", { method: "POST", body: JSON.stringify({ name: "MCP App manifest", version: "1.0.0", ontology_refs: [ontRef], data_recipe_refs: [], surface_descriptor_refs: [sdRef], evaluation_dataset_refs: [], benchmark_profile_refs: [], operator_contract_refs: [], mcp_contract_refs: [], owner_ref: OWNER, idempotency_key: "mnn-man-1" }) });
    const manRef = man.body?.manifest?.odk_manifest_id || man.body?.manifest?.ref || "";
    const dapp = await jd(DAEMON, "/v1/hypervisor/domain-apps", { method: "POST", body: JSON.stringify({ name: "MCP App", surface_descriptor_ref: sdRef, odk_manifest_ref: manRef, owner_ref: OWNER, idempotency_key: "mnn-dapp-1" }) });
    const dappRef = dapp.body?.domain_app?.domain_app_id || "";
    if (!(ontRef && revisionRef && sdRef && manRef && dappRef)) f(`odk_mesh:${ont.status}/${version.status}/${sd.status}/${man.status}/${dapp.status}:${JSON.stringify(sd.status === 201 ? (man.status === 201 ? dapp.body : man.body) : sd.body).slice(0, 400)}`);
    const pkg = await jd(DAEMON, "/v1/hypervisor/packages", { method: "POST", body: JSON.stringify({ owner_ref: OWNER, package_id: PKG, domain_app_ref: dappRef, idempotency_key: "mnn-pkg-1" }) });
    const packageHead = (await jd(DAEMON, `/v1/hypervisor/packages/${PKG}`)).body?.package?.agentgres?.head || "";
    if (!(pkg.status === 201 && packageHead)) f(`package:${pkg.status}:${JSON.stringify(pkg.body).slice(0, 300)}`);
    const release = await jd(DAEMON, `/v1/hypervisor/packages/${PKG}/releases`, { method: "POST", body: JSON.stringify({ idempotency_key: "mnn-rel-1", expected_package_head: packageHead, surface_distribution: "private_registry", surface_capability_depth: "propose", object_contract_refs: [`object-model://${NS}`], action_contract_refs: [`action://${NS}/open`], dependency_release_refs: [], evidence_refs: [`artifact://${NS}/conformance`] }) });
    // The digest the route's path takes is the tail of the admitted record's own release_ref
    // (`<package_ref>/release/<digest>`), read from the record rather than recomputed here.
    const releaseDigest = (release.body?.release?.record?.release_ref || "").split("/release/")[1] || "";
    const releaseHead = (await jd(DAEMON, `/v1/hypervisor/packages/${PKG}/releases/${encodeURIComponent(releaseDigest)}`)).body?.release?.agentgres?.head || "";
    if (!(release.status === 201 && releaseDigest && releaseHead)) f(`release:${release.status}:${JSON.stringify(release.body).slice(0, 300)}`);
    const install = await jd(DAEMON, `/v1/hypervisor/packages/${PKG}/releases/${encodeURIComponent(releaseDigest)}/installations`, { method: "POST", body: JSON.stringify({ idempotency_key: "mnn-inst-1", expected_release_head: releaseHead, installation_id: INST, visibility: "organization", allowed_object_contract_refs: [`object-model://${NS}`], allowed_action_refs: [`action://${NS}/open`] }) });
    const instPath = `/v1/hypervisor/packages/${PKG}/releases/${encodeURIComponent(releaseDigest)}/installations/${INST}`;
    const installationHead = (await jd(DAEMON, instPath)).body?.installation?.agentgres?.head || "";
    if (!(install.status === 201 && installationHead)) f(`install:${install.status}:${JSON.stringify(install.body).slice(0, 300)}`);
    const register = await jd(DAEMON, `${instPath}/registration`, { method: "POST", body: JSON.stringify({ idempotency_key: "mnn-reg-1", expected_installation_head: installationHead, display_name: "MCP App under test", supported_placements: ["applications_catalog", "open_application"], launch_modes: ["direct", "open_application"], supported_context_kinds: ["project"] }) });
    if (register.status !== 201) f(`register:${register.status}:${JSON.stringify(register.body).slice(0, 300)}`);
    const nativeRegistration = (await jd(DAEMON, `${instPath}/registration`)).body?.registration?.record ?? {};

    // --- clause 4 + 5: the App NORMALIZES, and it is the SAME record the native path serves
    const descriptorAnswer = await jd(DAEMON, `${T}/apps/${PKG}/descriptor`);
    const d = check("app_descriptor", descriptorAnswer, "mcp.app", "normalized", 200);
    if (d?.canonical_backing_ref !== SURFACE_REF) f(`app_descriptor_backing:${d?.canonical_backing_ref}`);
    const projectionFindings = LIB.appDescriptorFindings(d?.descriptor, nativeRegistration);
    if (projectionFindings.length) f(`app_descriptor_projection:${projectionFindings.slice(0, 3).join("|")}`);
    if (!Array.isArray(d?.backing_revision_refs) || !d.backing_revision_refs.length) f("app_descriptor_names_no_revision");
    const search = await jd(DAEMON, `${T}/apps/search`);
    const listed = check("app_search", search, "mcp.app", "normalized", 200);
    if (listed?.app_count !== 1 || listed?.apps?.[0]?.app_id !== PKG) f(`app_search:${listed?.app_count}:${listed?.apps?.[0]?.app_id}`);
    if (listed?.apps?.[0]?.effect_boundary !== nativeRegistration.effect_boundary) f("app_search_effect_boundary_drift");

    // --- clause 10: reading the App wrote nothing
    const digestOf = () => {
      const base = path.join(dataDir, "records");
      if (!fs.existsSync(base)) return "absent";
      const walk = (dir) => fs.readdirSync(dir, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name)).map((e) => {
        const p = path.join(dir, e.name);
        return e.isDirectory() ? `${e.name}/{${walk(p)}}` : `${e.name}:${sha256(fs.readFileSync(p))}`;
      }).join(",");
      return sha256(walk(base));
    };
    const before = digestOf();
    for (let i = 0; i < 3; i += 1) { await jd(DAEMON, `${T}/apps/${PKG}/descriptor`); await jd(DAEMON, `${T}/apps/search`); await jd(DAEMON, `${T}/resources/search`); }
    if (digestOf() !== before) f("reading_the_mcp_routes_changed_a_record_family");

    // --- clause 6: a recalled release is refused BY NAME, not described
    const recall = await jd(DAEMON, `/v1/hypervisor/packages/${PKG}/releases/${encodeURIComponent(releaseDigest)}/recall`, { method: "POST", body: JSON.stringify({ idempotency_key: "mnn-recall-1", expected_release_head: releaseHead, reason: "the App under test is withdrawn" }) });
    if (recall.status !== 200 && recall.status !== 201) f(`recall:${recall.status}:${JSON.stringify(recall.body).slice(0, 200)}`);
    else {
      const afterRecall = await jd(DAEMON, `${T}/apps/${PKG}/descriptor`);
      const rd = check("app_recalled", afterRecall, "mcp.app", "typed_unavailable", 404);
      if (rd?.refusal_code !== "extension_application_registration_absent") f(`app_recalled_refusal_code:${rd?.refusal_code}`);
      const searchAfter = await jd(DAEMON, `${T}/apps/search`);
      if (searchAfter.body?.app_count !== 0) f(`app_search_after_recall:${searchAfter.body?.app_count}`);
    }
  } catch (error) {
    f(`plane_threw:${error?.message ?? error}`);
  } finally {
    if (plane?.stop) await plane.stop().catch(() => {});
    fs.rmSync(dataDir, { recursive: true, force: true });
  }
  return { findings, observed, seconds: Math.round((Date.now() - started) / 1000) };
}

// ---- full ------------------------------------------------------------------------------------------------------------
async function runGate(g, workDir, floors, clauseN) {
  const label = `${clauseN}-${(g.floor || g.script).replace(/[^A-Za-z0-9]+/gu, "-")}`;
  const censusDir = path.join(workDir, "census", label);
  fs.mkdirSync(censusDir, { recursive: true });
  const env = { ...sanitizedVerifierBaseEnv(), ...process.env, IOI_VERIFIER_CENSUS_DIR: path.relative(ROOT, censusDir), CARGO_NET_OFFLINE: "true", IOI_ISOLATED_DAEMON_READY_TIMEOUT_MS: process.env.IOI_ISOLATED_DAEMON_READY_TIMEOUT_MS || "120000" };
  const argv = ["npm", "run", "-s", g.script, ...(g.workspace ? [`--workspace=${g.workspace}`] : [])];
  const iso = await runIsolated({ label, argv, cwd: ROOT, env, workDir, bridges: [], timeoutMs: (g.minutes ?? 15) * 60_000 });
  const classified = classifyLedger(iso.ledger, { declaredHosts: g.declaredHosts ?? [], declaredNames: g.declaredNames ?? [] });
  const logFile = path.join(workDir, `${label}.log`);
  const files = fs.existsSync(censusDir) ? fs.readdirSync(censusDir).filter((x) => x.endsWith(".json")).map((x) => path.join(censusDir, x)) : [];
  const evidenceFile = files[0] || (fs.existsSync(logFile) ? logFile : null);
  const floorRow = g.floor ? (floors.verifiers ?? []).find((r) => r.id === g.floor) : null;
  const censusJson = files[0] ? readJson(files[0]) : null;
  return {
    script: g.script,
    status: iso.status,
    seconds: iso.seconds,
    isolation: iso.isolation,
    ledger: {
      attempts: classified.counts?.attempts ?? 0,
      loopback: classified.counts?.loopback ?? 0,
      reach: (classified.undeclared?.length ?? 0) + (classified.undeclared_names?.length ?? 0),
      declared: classified.declared?.length ?? 0,
    },
    evidence: evidenceFile ? path.relative(ROOT, evidenceFile) : null,
    evidence_sha256: evidenceFile && fs.existsSync(evidenceFile) ? sha256(fs.readFileSync(evidenceFile)) : null,
    executed_assertions: censusJson?.executed_assertions ?? null,
    floor_expected: floorRow?.runtime_assertions ?? null,
    clause: clauseN,
  };
}

async function full() {
  const workDir = fs.mkdtempSync(path.join(os.tmpdir(), "mcp-normalization-harness-"));
  const floors = readJson(FLOORS);
  const probe = probeIsolation();
  if (!probe.strace.available) blocked(`the harness cannot record: ${probe.strace.detail}`);

  console.log("\n# CLIENT — the real stdio client against two loopback stub MCP servers");
  const client = clientLeg();
  evidence.client = client;
  console.log(`  → ${client.findings.length === 0 ? "green" : client.findings.join("; ")} in ${client.seconds}s`);

  console.log("\n# PLANE — one isolated daemon: fourteen refusals, the App positive, native equivalence, recall");
  const plane = await planeLeg();
  evidence.plane = plane;
  if (plane.blocked) blocked("the daemon binary is absent; build it before running the full gate");
  console.log(`  → ${plane.findings.length === 0 ? "green" : plane.findings.slice(0, 6).join("; ")} in ${plane.seconds}s · ${plane.observed?.contract_valid}/${plane.observed?.decisions} decisions contract-valid`);

  const selfRun = (name) => {
    const leg = name.startsWith("pure") ? { findings: evidence.pure?.findings ?? [] }
      : name.startsWith("source") ? { findings: evidence.source?.findings ?? [] }
      : name.startsWith("client") ? client
      : plane;
    return { script: name, status: leg.findings.length === 0 ? 0 : 1, seconds: leg.seconds ?? 0, evidence: leg, evidence_sha256: sha256(JSON.stringify(leg)), ledger: { attempts: 0, loopback: 0, reach: 0 } };
  };

  const done = new Map();
  const rows = [];
  for (const c of CLAUSES) {
    const row = { n: c.n, demand: c.demand, executed: [], absence: c.absence || null, scheduled: c.scheduled || null };
    for (const g of c.executed_by ?? []) {
      if (g.kind === "self") { row.executed.push(selfRun(g.script)); continue; }
      if (!done.has(g.script)) {
        console.log(`\n# ${g.script} — inside the harness (clause ${c.n})`);
        done.set(g.script, await runGate(g, workDir, floors, c.n));
        const r = done.get(g.script);
        console.log(`  → exit ${r.status} in ${r.seconds}s · ${r.executed_assertions ?? "?"}${r.floor_expected != null ? `/${r.floor_expected}` : ""} · ledger ${r.ledger.attempts} attempts, ${r.ledger.loopback} loopback, ${r.ledger.reach} reach`);
      }
      row.executed.push(done.get(g.script));
    }
    rows.push(row);
  }
  const v = verdict(rows);
  evidence.clauses = rows;
  evidence.verdict = v;
  console.log(`\n=== VERDICT: ${v.kind.toUpperCase()}${v.failures.length ? ` — ${v.failures.join(" ; ")}` : ""}`);
  for (const a of v.absences) console.log(`NAMED  clause ${a.n}: ${a.what.slice(0, 170)} → ${a.owner.slice(0, 120)}`);
  return v;
}

// ---- main ---------------------------------------------------------------------------------------------------------------
(async () => {
  let exit = 0;
  if (MODE === "mutation") exit = (await mutation()) ? 0 : 1;
  else {
    await drills();
    const fails = results.filter((r) => !r.pass);
    console.log(`\n${results.length - fails.length}/${results.length} drills passed`);
    emitVerifierCensus({ verifierId: "mcp-non-tool-normalization", sourceUrl: import.meta.url, results });
    if (fails.length) exit = 1;
    else if (MODE === "full") { const v = await full(); exit = v.kind === "pass" ? 0 : v.kind === "named_failure" ? 2 : 1; }
  }
  const file = writeEvidence();
  console.log(`evidence: ${path.relative(ROOT, file)}`);
  process.exit(exit);
})().catch((error) => { console.error("verifier crashed:", error); writeEvidence(); process.exit(1); });
