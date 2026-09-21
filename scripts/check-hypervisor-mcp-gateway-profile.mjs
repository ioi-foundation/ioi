#!/usr/bin/env node
// check:hypervisor-mcp-gateway-profile — M01.11: the subject-scoped outward Hypervisor MCP gateway, as a
// gate (docs/architecture/components/connectors-tools/contracts.md § Hypervisor MCP Gateway Profile and
// § Profile versions and the source-neutral builder kind; ADR 0055; ACC-1 clauses 8 and N6; register R-220).
//
// CANON. One immutable versioned HypervisorMCPGatewayProfile binds ONE subject and ONE use to exact
// requirement and exposure-manifest hashes, and an external model or harness receives only the capabilities
// and leased context that profile admitted. A profile grants no authority by itself. Lifecycle state may
// only REDUCE; a changed declared body is a successor; a successor that adds anything repeats admission;
// and a tool arriving over MCP reaches the same final invoker as the native call.
//
// WHAT THIS RUNNER IS. Each clause is EXECUTED by one of this runner's own legs, by a floored gate that
// already proves it, or NAMED — a typed absence with an owner, or a scheduled leg with its prerequisite and
// ruling. The runner's own legs:
//   PURE    — the oracle in apps/hypervisor/scripts/lib/mcp-gateway-profile.mjs over constructed profiles:
//             the closed kind sets and the no-fallback version rule, the admission members, the pairing
//             posture, the read-only contradiction, the source-neutral builder's two halves, the widening
//             rule member by member including the peer risk class, the lifecycle reduction that may not
//             move the content hash, the resolver that issues nothing, and the delegating call.
//   SOURCE  — the daemon's risk ladder and content-hash exclusion set equal the gate's; it validates
//             against all three registered contracts; the retired underscored scheme is gone; the eleven
//             operations are mounted and every one is classified in the table that refuses at STARTUP; the
//             two outward tool routes resolve a profile and still refuse without one; canon's binding.
//   PLANE   — full mode, one isolated daemon: a requirement resolved without issuing anything; a genesis
//             profile admitted; a NARROWING successor admitted under the same decision; a WIDENING
//             successor refused without a fresh admission and admitted with one; a lifecycle reduction that
//             does not move the content hash; a revoked profile refusing a call; a tool outside the frozen
//             exposure manifest refused; and the SAME tool invoked natively and through the gateway on a
//             fresh idempotency namespace, compared member for member.
//
//   --drills           CI-bound, seconds: PURE, SOURCE, the binding and the verdict rules. No daemon.
//   --mutation         planted defects against the oracle — each must go red.
//   (default)          the full gate: the drills, PLANE, then the composed gates inside the
//                      isolated-egress harness. Exit 0 pass, 2 named failure, 1 fail.
//   --evidence <path>  also write the evidence there.

import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { emitVerifierCensus } from "../apps/hypervisor/scripts/lib/verifier-census.mjs";
import { sanitizedVerifierBaseEnv, startIsolatedPlane } from "../apps/hypervisor/scripts/lib/isolated-daemon.mjs";
import { classifyLedger, probeIsolation, runIsolated } from "./lib/egress-harness.mjs";
import * as LIB from "../apps/hypervisor/scripts/lib/mcp-gateway-profile.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, "..");
const APP_DIR = path.join(ROOT, "apps", "hypervisor");
const APP = "@ioi/hypervisor-app";
const FLOORS = path.join(APP_DIR, "verifier-floors.v1.json");
const LIB_PATH = path.join(APP_DIR, "scripts", "lib", "mcp-gateway-profile.mjs");
const GATEWAY_ROUTES = path.join(ROOT, "crates", "node", "src", "bin", "hypervisor_daemon_routes", "mcp_gateway_routes.rs");
const OPERABILITY_ROUTES = path.join(ROOT, "crates", "node", "src", "bin", "hypervisor_daemon_routes", "operability_routes.rs");
const DAEMON_MAIN = path.join(ROOT, "crates", "node", "src", "bin", "hypervisor-daemon.rs");
const CANON = path.join(ROOT, "docs", "architecture", "components", "connectors-tools", "contracts.md");
const DOCTRINE = path.join(ROOT, "docs", "architecture", "components", "connectors-tools", "doctrine.md");
const ADR = path.join(ROOT, "docs", "decisions", "0055-the-outward-mcp-gateway-profile-is-registered-hyphen-scheme-and-its-heavy-builder-clause-is-retyped.md");

const argv = process.argv.slice(2);
const flag = (name) => argv.includes(name);
const flagValue = (name) => { const i = argv.indexOf(name); return i >= 0 ? argv[i + 1] : null; };
const MODE = flag("--mutation") ? "mutation" : flag("--drills") ? "drills" : "full";
const OWNER_Q = "owner question, R-220";

const gate = (script, floor, minutes) => ({ kind: "app", script, workspace: APP, floor, minutes });
const self = (name) => ({ kind: "self", script: `${name} (this runner)` });
const PURE = self("pure");
const SOURCE = self("source");
const PLANE = self("plane");
const TRANSPORT = gate("check:mcp-transport-normalization", "mcp-transport-normalization", 5);
const NON_TOOL = { kind: "root", script: "check:mcp-non-tool-normalization", minutes: 20 };
const CONTRACTS = { kind: "root", script: "check:architecture-contracts", minutes: 5, undrilled: "the contract registry's own gate; its oracle is the generated-versus-authored golden fixture battery in ioi-types, a cargo test rather than a mutate: script" };

export const CLAUSES = [
  { n: 1, demand: "the outward gateway is a REGISTERED contract before it is a route: the requirement envelope and both profile versions carry registered schemas, invariants and fixtures, the daemon validates every profile it admits against the contract its own schema version names, and a version this daemon does not read is refused by name rather than defaulted", executed_by: [SOURCE, PURE, CONTRACTS, PLANE] },
  { n: 2, demand: "one immutable versioned profile binds subject, key, origin, use, refs, exposure hash, privacy, budget, rate, expiry, revocation and receipt obligations — and the admitted revision FREEZES them: the content hash covers the declared body, the lifecycle projections bind it rather than entering it, and a revision belongs to its own family", executed_by: [PURE, SOURCE, PLANE] },
  { n: 3, demand: "versions do not fall back in either direction: a v1 profile presented to a v2 reader and a v2 profile presented to a v1 reader both refuse with the version named, because reading a v2 as a v1 by discarding the kind it does not recognise would admit the source-neutral builder as whatever the v1 reader defaulted to", executed_by: [PURE, PLANE] },
  { n: 4, demand: "the eight v2 profile kinds are a closed set with the seven v1 kinds unchanged, and `capability_construction_eval` is SOURCE-NEUTRAL: bound to one invocation, requiring no foundry, training or dataset-factory scope, and never substitutable for `foundry_eval_training`", executed_by: [PURE, SOURCE], absence: { what: "one representative admitted discovery or use per kind: this gate drives the profile LIFECYCLE for every kind and the CALL for the kinds whose exposure resolves to an admitted RuntimeToolContract; `connector_preview`, `foundry_eval_training` and `receipts_replay_proof` have no admitted backing contract on an isolated plane, so their calls are lifecycle-proven and use-named rather than executed", owner: `M06.4's replay surface and the Foundry plane (${OWNER_Q})` } },
  { n: 5, demand: "narrowing without rewrite and widening only by fresh admission: lifecycle state reduces effective access without touching the declared body, a changed body is a successor, and a successor that adds a tool, resource, scope, project, session, surface, extension, risk ceiling or expiry is refused unless it carries its own admission decision", executed_by: [PURE, PLANE, SOURCE] },
  { n: 6, demand: "a tool arriving over MCP normalizes to the same contract and reaches the same final invoker as the native path: the gateway checks the frozen exposure manifest, readiness, approval posture and bound session, then DELEGATES, and the two answers agree member for member on a fresh idempotency namespace", executed_by: [PLANE, PURE, SOURCE, NON_TOOL] },
  { n: 7, demand: "every non-tool primitive re-enters the M01.10 canonical normalization path rather than gaining an outward exception: the gateway exposes what the estate can honestly serve and refuses the rest in the same registered decision", executed_by: [NON_TOOL, SOURCE] },
  { n: 8, demand: "resolving a requirement ISSUES NOTHING: the resolver evaluates one exact immutable revision against one proposed use, names which member of the ceiling was exceeded when it refuses, and writes no profile and grants no scope; the package requirement lane and the live profile lane stay separate in the manifest and genesis schemas", executed_by: [PURE, PLANE, TRANSPORT] },
  { n: 9, demand: "the outward surface fails closed without a resolved profile: both existing outward tool routes refuse typed-unavailable when no subject resolves or no active profile is admitted, and the refusal grants nothing and carries neither a result nor a tool listing", executed_by: [SOURCE, PLANE, TRANSPORT] },
  { n: 10, demand: "authenticated pairing or subject proof, candidate-key and origin binding and an admitted-use basis: a room guest names the decision that admitted it, a registered worker names its registration, a paired local harness names its candidate key and pairing session, and a prompt-only posture may only ever propose", executed_by: [PURE, PLANE], absence: { what: "the LIVE local-agent pairing crossing — a real `LocalAgentPairingSessionEnvelope` issued to a paired harness, its one-time challenge consumed and its candidate key proven — which needs the pairing plane canon lists as planned; this gate proves the profile-side bindings the pairing would produce, and does not mint one", owner: `the LocalAgentPairingSessionEnvelope plane (${OWNER_Q}; canon's own front matter lists it planned)` } },
  { n: 11, demand: "upstream authority, policy and quarantine fence the gateway: a revoked, suspended, quarantined or expired profile stops effectful calls before provider mutation and answers a scoped failure, and expiry is derived rather than trusted from the record", executed_by: [PURE, PLANE], absence: { what: "propagation of a quarantine INTO dependent sessions, WorkRuns, connector calls and pending approvals, and the blast-radius report canon requires derived from admitted records; the gateway stops its own calls and does not yet notify what it fenced", owner: `M06.9's impact walker and the quarantine fence (${OWNER_Q})` } },
  { n: 12, demand: "the four declared gateway events and the quarantine receipt type are emitted by the plane that owns them, so a relying party can replay what a profile did rather than infer it from logs", executed_by: [], absence: { what: "`mcp.gateway_profile_registered`, `_used`, `_quarantined` and `_revoked` are declared in events-receipts-delivery-bundles.md and the events route DERIVES three of them from the profile revision chain rather than emitting them onto the event stream; `McpGatewayProfileQuarantineReceipt` has no producer, and `_used` has no record at all because a use writes the native path's receipt and not a gateway one", owner: `M06.1's event stream and the receipt family (${OWNER_Q})` } },
];

// ---- infrastructure ----------------------------------------------------------------------------------------
const results = [];
const evidence = { schema: "ioi.hypervisor-mcp-gateway-profile-evidence.v1", mode: MODE, started_at: new Date().toISOString(), drills: [], pure: null, source: null, plane: null, clauses: [], verdict: null, mutation: null };
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
  const file = path.join(dir, `hypervisor-mcp-gateway-profile-${MODE}-${evidence.started_at.replace(/[:.]/g, "-")}.json`);
  fs.writeFileSync(file, `${JSON.stringify(evidence, null, 2)}\n`);
  const extra = flagValue("--evidence");
  if (extra) { fs.mkdirSync(path.dirname(path.resolve(ROOT, extra)), { recursive: true }); fs.writeFileSync(path.resolve(ROOT, extra), `${JSON.stringify(evidence, null, 2)}\n`); }
  return file;
}
const readText = (p) => fs.readFileSync(p, "utf8");
const readJson = (p) => JSON.parse(fs.readFileSync(p, "utf8"));
const sha256 = (s) => `sha256:${crypto.createHash("sha256").update(s).digest("hex")}`;

const H = (seed) => `sha256:${crypto.createHash("sha256").update(seed).digest("hex")}`;

/** A profile the oracle should accept, built member by member so a drill can spoil exactly one. */
function profile(over = {}) {
  return {
    schema_version: LIB.PROFILE_V1_VERSION,
    gateway_profile_id: "mcp-gateway://auditor",
    profile_revision_ref: `mcp-gateway://auditor/revision/${H("r1")}`,
    predecessor_profile_revision_ref: null,
    profile_content_hash: H("body1"),
    resolved_requirement_revision_refs: [],
    resolved_requirement_set_hash: H("req"),
    exposure_manifest_hash: H("exposure"),
    display_name: "Auditor",
    audience: "external_agent",
    profile_kind: "project_session",
    subject_ref: "agent://external/auditor",
    local_agent_pairing_session_ref: null,
    candidate_public_key_ref: null,
    project_refs: [],
    session_refs: [],
    outcome_room_ref: null,
    room_participant_lease_ref: null,
    room_admission_decision_ref: null,
    worker_registration_ref: null,
    admission_basis: "not_applicable",
    invocation_scope_refs: [],
    pairing_execution_posture: "not_applicable",
    pairing_contribution_lane: "not_applicable",
    surface_refs: [],
    exposed_tools: [],
    exposed_resources: [],
    exposed_prompt_import_contract_refs: [],
    elicitation_contract_refs: [],
    external_task_contract_refs: [],
    extension_application_refs: [],
    authority_client_ref: "wallet-client://auditor",
    origin_binding_ref: "origin://https.auditor.example",
    authority_scope_refs: [],
    privacy_posture_ref: "privacy://redacted",
    budget_policy_ref: "policy://budget",
    rate_limit_ref: "policy://rate",
    quarantine_policy_ref: "policy://quarantine",
    dependent_refs: [],
    issued_after_required_admission: true,
    prompt_only_proposal: false,
    expires_at: "2026-12-31T23:59:59Z",
    revocation_ref: null,
    quarantine_advisory_refs: [],
    status: "active",
    last_use_ref: null,
    manifest_ref: "mcp-manifest://auditor",
    admission_decision_ref: "decision://hypervisor/gateway/1",
    admission_receipt_ref: "receipt://hypervisor/gateway/1",
    receipt_refs: [],
    ...over,
  };
}

const tool = (name, risk, over = {}) => ({
  mcp_tool_name: name,
  backing_contract_revision_ref: "tool://project.inspect/revision/1.0.0",
  backing_contract_content_hash: H(name),
  contract_kind: "runtime_tool_contract",
  risk_class: risk,
  effect_class: risk,
  readiness: "ready",
  dry_run_required: false,
  approval_required: false,
  authority_scopes_required: [],
  receipt_obligations: ["ToolExecutionReceipt"],
  ...over,
});

// ---- PURE ---------------------------------------------------------------------------------------------------
export function pureFindings(lib) {
  const f = [];
  const clean = (what, findings) => { if (findings.length) f.push(`${what}_rejected_a_clean_case:${findings.slice(0, 2).join("|")}`); };
  const dirty = (what, findings, needle) => {
    if (!findings.length) f.push(`${what}_accepted`);
    else if (needle && !findings.some((x) => x.includes(needle))) f.push(`${what}_wrong_finding:${findings[0]}`);
  };

  // 1. the clean shapes
  clean("a v1 profile", lib.profileFindings(profile()));
  clean("a v2 profile", lib.profileFindings(profile({ schema_version: lib.PROFILE_V2_VERSION })));
  clean("the source-neutral builder", lib.profileFindings(profile({
    schema_version: lib.PROFILE_V2_VERSION,
    profile_kind: lib.V2_ONLY_KIND,
    invocation_scope_refs: ["session://build-1"],
    exposed_tools: [tool("construct", "local_write")],
  })));

  // 2. versions do not fall back
  dirty("a v2-only kind in a v1 document", lib.profileFindings(profile({ profile_kind: lib.V2_ONLY_KIND })), "v2-only kind");
  dirty("a version this estate does not read", lib.profileFindings(profile({ schema_version: "ioi.hypervisor-mcp-gateway-profile.v3" })), "not a gateway profile version");
  dirty("a kind outside the closed set", lib.profileFindings(profile({ profile_kind: "whatever" })), "closed kind set");

  // 3. identity
  dirty("the retired underscored scheme", lib.profileFindings(profile({ gateway_profile_id: "mcp_gateway://auditor" })), "canonical mcp-gateway:// scheme");
  dirty("a revision belonging to another family", lib.profileFindings(profile({ profile_revision_ref: `mcp-gateway://someone-else/revision/${H("r1")}` })), "another profile family");
  dirty("a revision that is not content-addressed", lib.profileFindings(profile({ profile_revision_ref: "mcp-gateway://auditor/revision/1" })), "content-addressed");

  // 4. admission
  dirty("a profile not issued after admission", lib.profileFindings(profile({ issued_after_required_admission: false })), "issued after");
  for (const key of ["admission_decision_ref", "admission_receipt_ref"]) {
    dirty(`a profile naming no ${key}`, lib.profileFindings(profile({ [key]: "" })), key);
  }
  dirty("a revoked profile with no revocation ref", lib.profileFindings(profile({ status: "revoked", revocation_ref: null })), "revocation ref");
  dirty("a room guest with no room admission", lib.profileFindings(profile({ admission_basis: "room_guest" })), "room admission");
  dirty("a registered worker with no registration", lib.profileFindings(profile({ admission_basis: "registered_worker_invocation" })), "worker registration");
  dirty("a local harness with no candidate key", lib.profileFindings(profile({ audience: "local_harness" })), "candidate_public_key_ref");

  // 5. the pairing posture
  dirty("a prompt-only posture with an instrumented lane", lib.profileFindings(profile({ pairing_execution_posture: "prompt_only", pairing_contribution_lane: "instrumented_candidate", prompt_only_proposal: true })), "instrumented contribution lane");
  dirty("a prompt-only posture not marked proposal-only", lib.profileFindings(profile({ pairing_execution_posture: "prompt_only", pairing_contribution_lane: "proposal_only", prompt_only_proposal: false })), "proposal-only");

  // 6. the read-only contradiction and the wire-name rule
  dirty("a read-only profile exposing an approval-requiring tool", lib.profileFindings(profile({ profile_kind: "discovery_readonly", exposed_tools: [tool("t", "read", { approval_required: true })] })), "approval-requiring");
  dirty("a read-only profile exposing an effectful tool", lib.profileFindings(profile({ profile_kind: "discovery_readonly", exposed_tools: [tool("t", "funds")] })), "effect class");
  dirty("two exposed tools under one wire name", lib.profileFindings(profile({ exposed_tools: [tool("t", "read"), tool("t", "read")] })), "one wire name");
  dirty("an exposed resource with no context lease", lib.profileFindings(profile({ exposed_resources: [{ mcp_resource_uri: "hv://x", backing_projection_ref: "view://x", redaction_policy_ref: "policy://r" }] })), "context lease");

  // 7. the source-neutral builder's two halves
  const builder = (over) => profile({ schema_version: lib.PROFILE_V2_VERSION, profile_kind: lib.V2_ONLY_KIND, invocation_scope_refs: ["session://b"], exposed_tools: [tool("c", "local_write")], ...over });
  dirty("a builder bound to no invocation", lib.profileFindings(builder({ invocation_scope_refs: [] })), "no invocation scope");
  for (const scope of ["scope:foundry.train", "scope:training.read", "scope:dataset-factory.read"]) {
    dirty(`a builder requiring ${scope}`, lib.profileFindings(builder({ exposed_tools: [tool("c", "local_write", { authority_scopes_required: [scope] })] })), "training scope");
  }

  // 8. the widening rule, member by member
  const wide = profile({ exposed_tools: [tool("a", "read"), tool("b", "read")], authority_scope_refs: ["scope:x", "scope:y"], project_refs: ["project://a", "project://b"] });
  const narrow = profile({ exposed_tools: [tool("a", "read")], authority_scope_refs: ["scope:x"], project_refs: ["project://a"] });
  clean("a narrowing successor", lib.wideningFindings(wide, narrow));
  for (const [what, needle] of [["the exposed tool set", "exposed tool set"], ["the authority scope set", "authority scope set"], ["the project set", "project set"]]) {
    dirty(`a successor widening ${what}`, lib.wideningFindings(narrow, wide), needle);
  }
  dirty("a successor raising the risk ceiling", lib.wideningFindings(profile({ exposed_tools: [tool("a", "read")] }), profile({ exposed_tools: [tool("a", "funds")] })), "risk ceiling rises");
  dirty("a successor reaching the peer physical-action class", lib.wideningFindings(profile({ exposed_tools: [tool("a", "system_destructive")] }), profile({ exposed_tools: [tool("a", "physical_action")] })), "physical-action");
  dirty("a successor extending the expiry", lib.wideningFindings(profile(), profile({ expires_at: "2027-12-31T23:59:59Z" })), "expiry extends");
  dirty("a successor changing the subject", lib.wideningFindings(profile(), profile({ subject_ref: "agent://external/other" })), "subject changes");
  dirty("a successor gaining a ceiling where there was none", lib.wideningFindings(profile({ exposed_tools: [] }), profile({ exposed_tools: [tool("a", "read")] })), "gains a risk ceiling");

  // 9. the head, the fork and derived expiry
  const genesis = profile();
  const successor = profile({ profile_revision_ref: `mcp-gateway://auditor/revision/${H("r2")}`, predecessor_profile_revision_ref: genesis.profile_revision_ref });
  const fork = profile({ profile_revision_ref: `mcp-gateway://auditor/revision/${H("r3")}`, predecessor_profile_revision_ref: genesis.profile_revision_ref });
  if (lib.currentRevision([successor, genesis], "mcp-gateway://auditor")?.profile_revision_ref !== successor.profile_revision_ref) f.push("head_not_derived_from_the_chain");
  if (lib.currentRevision([genesis, successor, fork], "mcp-gateway://auditor") !== null) f.push("fork_answered_with_a_head");
  if (lib.currentRevision([], "mcp-gateway://auditor") !== null) f.push("empty_family_answered_with_a_head");
  if (lib.effectiveStatus(profile({ expires_at: "2020-01-01T00:00:00Z" }), "2026-09-21T00:00:00Z") !== "expired") f.push("a_past_expiry_did_not_read_expired");
  if (lib.effectiveStatus(profile({ status: "revoked" }), "2026-01-01T00:00:00Z") !== "revoked") f.push("a_revoked_profile_read_as_something_else");

  // 10. the lifecycle reduction
  const before = profile();
  clean("a lifecycle reduction", lib.lifecycleFindings(before, { ...before, status: "revoked", revocation_ref: "revocation://1" }));
  dirty("a lifecycle change back to active", lib.lifecycleFindings(before, { ...before, status: "active" }), "not a reduction");
  dirty("a lifecycle change editing the declared body", lib.lifecycleFindings(before, { ...before, status: "suspended", exposed_tools: [tool("a", "read")] }), "edited the declared body");
  dirty("a lifecycle change moving the content hash", lib.lifecycleFindings(before, { ...before, status: "suspended", profile_content_hash: H("other") }), "moved the content hash");
  dirty("a revocation naming no revocation ref", lib.lifecycleFindings(before, { ...before, status: "revoked" }), "no revocation ref");
  // The excluded set is what makes the reduction hash-stable; spoiling one member must be visible.
  for (const excluded of lib.EXCLUDED_FROM_CONTENT_HASH) {
    if (excluded === "profile_content_hash") continue;
    const moved = { ...before, status: "suspended", [excluded]: excluded.endsWith("_refs") ? ["x://1"] : "x://1" };
    clean(`a lifecycle reduction touching ${excluded}`, lib.lifecycleFindings(before, moved).filter((x) => x.includes("declared body")));
  }

  // 11. the resolver issues nothing
  const resolution = (over = {}) => ({ requirement_revision_ref: `mcp-gateway-requirement://a/revision/${H("q")}`, resolvable: true, exceeded: [], profile_issued: false, authority_granted: false, ...over });
  clean("a resolution", lib.resolutionFindings(resolution()));
  dirty("a resolution issuing a profile", lib.resolutionFindings(resolution({ profile_issued: true })), "profile was issued");
  dirty("a resolution granting authority", lib.resolutionFindings(resolution({ authority_granted: true })), "authority was granted");
  dirty("a resolution refusing without naming what exceeded", lib.resolutionFindings(resolution({ resolvable: false })), "naming which member");
  dirty("a resolution resolving while naming exceeded members", lib.resolutionFindings(resolution({ exceeded: ["x"] })), "while naming exceeded");
  dirty("a resolution for no exact revision", lib.resolutionFindings(resolution({ requirement_revision_ref: "mcp-gateway-requirement://a" })), "exact immutable");

  // 12. the delegating call
  const call = (over = {}) => ({ authority_granted: false, final_invoker: "RuntimeAgentService.handle_action_execution", profile_revision_ref: `mcp-gateway://auditor/revision/${H("r1")}`, exposure_manifest_hash: H("exposure"), native_answer: { status: "admitted" }, ...over });
  clean("a delegating call", lib.callFindings(call()));
  dirty("a call claiming authority", lib.callFindings(call({ authority_granted: true })), "claims authority");
  dirty("a call reporting another final invoker", lib.callFindings(call({ final_invoker: "GatewayService.invoke" })), "not the native path");
  dirty("a call naming no exposure manifest", lib.callFindings(call({ exposure_manifest_hash: "" })), "exposure manifest hash");
  const { native_answer: _dropped, ...withoutNative } = call();
  dirty("a call that did not delegate", lib.callFindings(withoutNative), "did not delegate");

  // 13. parity
  const native = { status: "admitted", final_invoker: "RuntimeAgentService.handle_action_execution", contract: { revision_ref: "tool://a/revision/1" }, runtime_tool_contract_admission_receipt_ref: "receipt://a" };
  clean("native-versus-gateway parity", lib.parityFindings(native, call({ native_answer: native })));
  dirty("parity on a different contract", lib.parityFindings(native, call({ native_answer: { ...native, contract: { revision_ref: "tool://b/revision/1" } } })), "contract differs");
  dirty("parity with no native answer", lib.parityFindings(native, withoutNative), "no native answer");
  return f;
}

// ---- SOURCE -------------------------------------------------------------------------------------------------
export function sourceFindings(s) {
  const f = [];
  const { gateway, operability, daemonMain, canon, doctrine, adr, lib } = s;
  f.push(...lib.sourceParityFindings(gateway));
  const served = lib.codeOnly(String(gateway).split("#[cfg(test)]")[0]);

  // 1. the plane's own rules are in the code, not only in the doc comment
  for (const [what, pattern] of [
    ["the declared-body hash", /fn declared_body\(/u],
    ["the chain-derived head", /fn current_revision\(/u],
    ["the widening rule", /fn widening_findings\(/u],
    ["the derived expiry", /fn effective_status\(/u],
  ]) {
    if (!pattern.test(served)) f.push(`pin_${what.replace(/\s+/gu, "_")}_absent`);
  }
  if (!/mcp_gateway_profile_widened_without_fresh_admission/u.test(served)) f.push("pin_widening_is_not_refused_by_name");
  if (!/mcp_gateway_lifecycle_change_moved_the_content_hash/u.test(served)) f.push("pin_lifecycle_does_not_recheck_the_hash");
  if (!/mcp_gateway_tool_outside_the_exposure_manifest/u.test(served)) f.push("pin_exposure_manifest_is_not_enforced");
  if (!/mcp_gateway_profile_version_unknown/u.test(served)) f.push("pin_unknown_version_is_not_refused_by_name");
  if (!/"profile_issued": false/u.test(served)) f.push("pin_resolver_does_not_say_it_issued_nothing");

  // 2. ONE FINAL INVOKER. The gateway delegates rather than invoking.
  if (!/lifecycle_routes::handle_mcp_tool_invoke\(/u.test(served)) f.push("pin_gateway_does_not_delegate_to_the_native_invoker");
  if (!/"final_invoker": "RuntimeAgentService\.handle_action_execution"/u.test(served)) f.push("pin_gateway_does_not_name_the_native_final_invoker");

  // 3. the eleven operations are mounted, and every path is CLASSIFIED in the table that refuses at startup
  const mountedGateway = [...String(daemonMain).matchAll(/\.route\(\s*"(\/v1\/mcp\/gateway[^"]*)"/gu)].map((m) => m[1]);
  if (mountedGateway.length !== 9) f.push(`pin_gateway_route_count:${mountedGateway.length}≠9`);
  const classifications = String(operability).slice(
    String(operability).indexOf("pub(crate) const MCP_ROUTE_CLASSIFICATIONS"),
    String(operability).indexOf("pub(crate) fn verify_mcp_route_classification("),
  );
  for (const route of mountedGateway) {
    if (!classifications.includes(`"${route}"`)) f.push(`pin_mounted_gateway_route_unclassified:${route}`);
  }
  for (const handler of [
    "handle_gateway_requirement_list", "handle_gateway_requirement_resolve", "handle_gateway_list",
    "handle_gateway_create", "handle_gateway_get", "handle_gateway_patch", "handle_gateway_revoke",
    "handle_gateway_manifest", "handle_gateway_call", "handle_gateway_events", "handle_gateway_receipts",
  ]) {
    if (!String(daemonMain).includes(`mcp_gateway_routes::${handler}`)) f.push(`pin_operation_unmounted:${handler}`);
  }

  // 4. the outward tool surface RESOLVES and still refuses without a profile — the retyped negative pin
  if (!/active_profile_for_subject\(/u.test(operability)) f.push("pin_outward_routes_do_not_resolve_a_profile");
  if (!/mcp_gateway_profile_unavailable/u.test(operability)) f.push("pin_outward_refusal_branch_deleted");
  if (/FORWARDED_AUTH_HEADERS/u.test(operability)) f.push("pin_outward_bypass_returned");

  // 5. canon and the decision say what the code does
  if (!/Profile versions and the source-neutral builder kind/u.test(canon)) f.push("pin_canon_v2_section_absent");
  if (!canon.includes(lib.V2_ONLY_KIND)) f.push("pin_canon_does_not_name_the_eighth_kind");
  if (!/VERSIONS DO NOT FALL BACK|Versions do not fall back|versions do not fall back/u.test(canon)) f.push("pin_canon_has_no_cross_version_rule");
  if (!doctrine.includes(lib.V2_ONLY_KIND)) f.push("pin_doctrine_does_not_name_the_eighth_kind");
  if (/mcp_gateway:\/\//u.test(canon) || /mcp_gateway:\/\//u.test(doctrine)) f.push("pin_canon_still_carries_the_retired_scheme");
  if (!/Status: Accepted/u.test(adr)) f.push("pin_adr_not_accepted");
  return f;
}

function sourceInputs() {
  return {
    gateway: readText(GATEWAY_ROUTES),
    operability: readText(OPERABILITY_ROUTES),
    daemonMain: readText(DAEMON_MAIN),
    canon: readText(CANON),
    doctrine: readText(DOCTRINE),
    adr: readText(ADR),
    lib: LIB,
  };
}

// ---- the binding --------------------------------------------------------------------------------------------
export function bindingFindings({ rootPkg, appPkg, floors, ci }) {
  const f = [];
  for (const script of ["check:hypervisor-mcp-gateway-profile", "mutate:hypervisor-mcp-gateway-profile"]) {
    if (!rootPkg.scripts?.[script]) f.push(`root_script_missing:${script}`);
  }
  if (!appPkg.scripts?.["check:hypervisor-mcp-gateway-profile"]) f.push("app_drills_script_missing");
  const rows = floors.verifiers ?? [];
  const named = (id) => rows.find((r) => r.id === id);
  for (const id of ["hypervisor-mcp-gateway-profile", "mcp-transport-normalization"]) {
    const row = named(id);
    if (!row) f.push(`floor_row_missing:${id}`);
    else if (!(Number.isInteger(row.runtime_assertions) && row.runtime_assertions > 0)) f.push(`floor_row_without_a_floor:${id}`);
    else if (!/^[0-9a-f]{64}$/u.test(row.assertion_names_sha256 ?? "")) f.push(`floor_row_without_a_name_digest:${id}`);
    else if (!(typeof row.note === "string" && row.note.length > 200)) f.push(`floor_row_without_a_note:${id}`);
    else if (!fs.existsSync(path.resolve(ROOT, row.source))) f.push(`floor_row_source_missing:${id}`);
  }
  if (!/check:hypervisor-mcp-gateway-profile/u.test(ci)) f.push("gate_not_ci_bound");
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

// ---- drills ---------------------------------------------------------------------------------------------------
async function drills() {
  const pure = pureFindings(LIB);
  evidence.pure = { findings: pure };
  ok("PURE — the oracle refuses every profile, successor, lifecycle change, resolution and call that claims more than it was admitted for, and accepts the clean shapes", pure.length === 0, pure.slice(0, 4).join(" ; "));
  const src = sourceFindings(sourceInputs());
  evidence.source = { findings: src };
  ok("SOURCE — the daemon's ladder and exclusion set equal the gate's, it validates against all three registered contracts, the eleven operations are mounted and classified, the outward routes resolve and still refuse without a profile, and canon and ADR 0055 say what the code does", src.length === 0, src.slice(0, 4).join(" ; "));
  const binding = bindingFindings({
    rootPkg: readJson(path.join(ROOT, "package.json")),
    appPkg: readJson(path.join(APP_DIR, "package.json")),
    floors: readJson(FLOORS),
    ci: fs.readdirSync(path.join(ROOT, ".github", "workflows")).map((file) => readText(path.join(ROOT, ".github", "workflows", file))).join("\n"),
  });
  ok("BINDING — the gate is floored with an existing source and CI-bound, every clause is executed or named with an owner, and the twelve clauses are present", binding.length === 0, binding.slice(0, 4).join(" ; "));
  const v = verdict([{ n: 1, executed: [{ script: "x", status: 0, evidence: {}, evidence_sha256: "s" }] }]);
  ok("VERDICT — a table missing eleven of its twelve rows is a FAIL, not a pass", v.kind === "fail" && v.failures.includes("row_missing:12"), v.failures.slice(0, 2).join(" ; "));
  const full = verdict([...Array(12)].map((_, i) => ({ n: i + 1, executed: [{ script: "x", status: 0, evidence: {}, evidence_sha256: "s" }] })));
  ok("VERDICT — twelve green rows with no absence is a PASS", full.kind === "pass", full.failures.slice(0, 2).join(" ; "));
  const named = verdict([...Array(12)].map((_, i) => ({ n: i + 1, executed: [{ script: "x", status: 0, evidence: {}, evidence_sha256: "s" }], absence: i === 3 ? { what: "a named absence long enough to be real", owner: "someone" } : null })));
  ok("VERDICT — one named absence is a NAMED FAILURE, never a pass", named.kind === "named_failure" && named.absences.length === 1, named.kind);
  const unevidenced = verdict([...Array(12)].map((_, i) => ({ n: i + 1, executed: [{ script: "x", status: 0 }] })));
  ok("VERDICT — a gate that reports success without evidence is fabricated, not green", unevidenced.kind === "fail" && unevidenced.failures.every((x) => x.includes("fabricated")), unevidenced.failures[0]);
  const reached = verdict([...Array(12)].map((_, i) => ({ n: i + 1, executed: [{ script: "x", status: 0, evidence: {}, evidence_sha256: "s", ledger: { attempts: 1, loopback: 0, reach: 1 } }] })));
  ok("VERDICT — a gate that reached a non-loopback destination fails, whatever it returned", reached.kind === "fail" && reached.failures.every((x) => x.includes("undeclared_egress")), reached.failures[0]);
  const belowFloor = verdict([...Array(12)].map((_, i) => ({ n: i + 1, executed: [{ script: "x", status: 0, evidence: {}, evidence_sha256: "s", floor_expected: 9, executed_assertions: 2 }] })));
  ok("VERDICT — a gate below its floor fails even at exit 0", belowFloor.kind === "fail" && belowFloor.failures.every((x) => x.includes("below_floor")), belowFloor.failures[0]);
}

// ---- mutation -------------------------------------------------------------------------------------------------
async function mutation() {
  const original = readText(LIB_PATH);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "mcp-gateway-mutation-"));
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
  const src = (mod) => {
    // Hand the mutated oracle a DELIBERATELY BROKEN daemon source: a rule that passes on the real tree
    // cannot die when it is deleted, so the mutant is measured against a tree that violates it.
    const inputs = sourceInputs();
    const f = [];
    const broken = inputs.gateway.replace('"system_destructive",', "");
    if (!mod.sourceParityFindings(broken).some((x) => x.includes("system_destructive"))) f.push("a dropped ladder member was accepted");
    const retired = inputs.gateway.replace("#[cfg(test)]", 'const OLD: &str = "mcp_gateway://x";\n#[cfg(test)]');
    if (!mod.sourceParityFindings(retired).some((x) => x.includes("retired underscored"))) f.push("the retired scheme was accepted");
    const uncontracted = inputs.gateway.replaceAll("validate_architecture_contract(", "skip(");
    if (!mod.sourceParityFindings(uncontracted).some((x) => x.includes("validates against none"))) f.push("a daemon that validates nothing was accepted");
    return f;
  };

  await mutate("the oracle stops refusing a v2-only kind in a v1 document", (t) => t.replace('if (version === PROFILE_V1_VERSION && strAt(profile, "profile_kind") === V2_ONLY_KIND) {', "if (false) {"), pure);
  await mutate("an unknown version is accepted", (t) => t.replace("if (kinds === null) {", "if (false) {"), pure);
  await mutate("the retired underscored profile id is accepted", (t) => t.replace('if (!PROFILE_ID_PATTERN.test(strAt(profile, "gateway_profile_id"))) {', "if (false) {"), pure);
  await mutate("a revision may belong to another family", (t) => t.replace("if (id && revision && !revision.startsWith(`${id}/revision/`)) {", "if (false) {"), pure);
  await mutate("a profile need not claim it was issued after admission", (t) => t.replace("if (profile.issued_after_required_admission !== true) {", "if (false) {"), pure);
  await mutate("a revoked profile need not name its revocation", (t) => t.replace('if (strAt(profile, "status") === "revoked" && !strAt(profile, "revocation_ref")) {', "if (false) {"), pure);
  await mutate("a room guest need not name its room", (t) => t.replace('if (strAt(profile, "admission_basis") === "room_guest" && !strAt(profile, "room_admission_decision_ref")) {', "if (false) {"), pure);
  await mutate("a local harness need not name its candidate key", (t) => t.replace('if (strAt(profile, "audience") === "local_harness") {', "if (false) {"), pure);
  await mutate("a prompt-only posture may carry an instrumented lane", (t) => t.replace('if (strAt(profile, "pairing_execution_posture") === "prompt_only") {', "if (false) {"), pure);
  await mutate("a read-only profile may expose an effectful tool", (t) => t.replace('if (strAt(profile, "profile_kind") === "discovery_readonly") {', "if (false) {"), pure);
  await mutate("two exposed tools may share one wire name", (t) => t.replace("if (new Set(names).size !== names.length) {", "if (false) {"), pure);
  await mutate("an exposed resource need not name a lease", (t) => t.replace('if (!strAt(resource, "required_context_lease_ref")) {', "if (false) {"), pure);
  await mutate("the source-neutral builder need not be bound to an invocation", (t) => t.replace("if (!(profile.invocation_scope_refs ?? []).length) {", "if (false) {"), pure);
  await mutate("the source-neutral builder may require a training scope", (t) => t.replace("if (/^scope:(foundry|training|dataset-factory)\\./u.test(scope)) {", "if (false) {"), pure);
  await mutate("a widened tool set is not a widening", (t) => t.replace("const gained = [...after].filter((entry) => !before.has(entry));", "const gained = [];"), pure);
  await mutate("a risen risk ceiling is not a widening", (t) => t.replace("} else if (after !== null && before !== null && riskRank(after) > riskRank(before)) {", "} else if (false) {"), pure);
  await mutate("the peer physical-action class is inherited", (t) => t.replace("if (after === PEER_RISK_CLASS) {", "if (false) {"), pure);
  await mutate("an extended expiry is not a widening", (t) => t.replace('if (strAt(next, "expires_at") > strAt(previous, "expires_at")) {', "if (false) {"), pure);
  await mutate("a changed subject is not a widening", (t) => t.replace('if (strAt(previous, "subject_ref") !== strAt(next, "subject_ref")) {', "if (false) {"), pure);
  await mutate("a fork answers with a head", (t) => t.replace("return heads.length === 1 ? heads[0] : null;", "return heads[0] ?? null;"), pure);
  await mutate("expiry is trusted from the record instead of derived", (t) => t.replace('return strAt(profile, "expires_at") <= now ? "expired" : "active";', 'return "active";'), pure);
  await mutate("a lifecycle change may edit the declared body", (t) => t.replace("if (JSON.stringify(declaredBody(before)) !== JSON.stringify(declaredBody(after))) {", "if (false) {"), pure);
  await mutate("a lifecycle change may move the content hash", (t) => t.replace('if (strAt(before, "profile_content_hash") !== strAt(after, "profile_content_hash")) {', "if (false) {"), pure);
  await mutate("a lifecycle change back to active is a reduction", (t) => t.replace("if (!REDUCING_STATES.includes(target)) {", "if (false) {"), pure);
  await mutate("the resolver may issue a profile", (t) => t.replace('if (answer.profile_issued !== false) findings.push("the resolver claims a profile was issued");', ""), pure);
  await mutate("the resolver may grant authority", (t) => t.replace('if (answer.authority_granted !== false) findings.push("the resolver claims authority was granted");', ""), pure);
  await mutate("the resolver may refuse without naming what exceeded", (t) => t.replace("if (answer.resolvable === false && !(answer.exceeded ?? []).length) {", "if (false) {"), pure);
  await mutate("a gateway call may claim authority", (t) => t.replace('if (answer.authority_granted !== false) findings.push("the gateway call claims authority");', ""), pure);
  await mutate("a gateway call may report another final invoker", (t) => t.replace('if (strAt(answer, "final_invoker") !== "RuntimeAgentService.handle_action_execution") {', "if (false) {"), pure);
  await mutate("a gateway call need not delegate", (t) => t.replace('if (!("native_answer" in answer)) {', "if (false) {"), pure);
  await mutate("parity stops comparing the admitted members", (t) => t.replace("if (a !== b) findings.push(`${member} differs: native ${a.slice(0, 80)} ≠ gateway ${b.slice(0, 80)}`);", ""), pure);
  await mutate("the daemon's risk ladder may drop a member", (t) => t.replace("      findings.push(`the daemon's risk ladder omits ${entry}`);", ""), src);
  await mutate("the daemon may carry the retired scheme again", (t) => t.replace("if (/mcp_gateway:\\/\\//u.test(served)) {", "if (false) {"), src);
  await mutate("the daemon may validate against nothing", (t) => t.replace("if (!/validate_architecture_contract\\(/u.test(served)) {", "if (false) {"), src);
  await mutate("a source pin may read explanatory comments again", (t) => t.replace('.filter((line) => !/^\\s*\\/\\//u.test(line))', ".filter(() => true)"), (mod) => {
    const prose = 'const X: &str = "x";\n// this module must never carry mcp_gateway:// again\n';
    return mod.sourceParityFindings(prose).some((x) => x.includes("retired underscored")) ? ["a source pin fired on prose"] : [];
  });
  fs.rmSync(dir, { recursive: true, force: true });
  evidence.mutation = { planted, caught };
  console.log(`\n${caught}/${planted} planted defects caught`);
  return caught === planted && planted >= 30;
}

// ---- main ---------------------------------------------------------------------------------------------------------------
(async () => {
  let exit = 0;
  if (MODE === "mutation") exit = (await mutation()) ? 0 : 1;
  else {
    await drills();
    const fails = results.filter((r) => !r.pass);
    console.log(`\n${results.length - fails.length}/${results.length} drills passed`);
    emitVerifierCensus({ verifierId: "hypervisor-mcp-gateway-profile", sourceUrl: import.meta.url, results });
    if (fails.length) exit = 1;
    else if (MODE === "full") { console.log("\n(full mode's PLANE leg and composed gates are the next slice; the drills stand alone)"); exit = 2; }
  }
  const file = writeEvidence();
  console.log(`evidence: ${path.relative(ROOT, file)}`);
  process.exit(exit);
})().catch((error) => { console.error("verifier crashed:", error); writeEvidence(); process.exit(1); });
