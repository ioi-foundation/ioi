#!/usr/bin/env node
// check:connected-access-cockpit — M08.16: the connected-access and delegated-authority cockpit, as a gate
// (docs/architecture/components/wallet-network/api-authority-scopes.md § Provider Connection Binding and
// doctrine.md § the connected-access journey; ACC-3 clause E and ACC-10; register R-221).
//
// CANON. Embedded product settings, the Hypervisor Connections cockpit and an advanced wallet view expose
// the SAME owner-backed connect, inspect, reauthorize, disconnect and receipt lifecycle over ONE daemon.
// They distinguish provider REACHABILITY from delegated AUTHORITY, show exact dependents, and render no
// secret. Every presentation uses the same M03.16 operations and state; none keeps a surface-owned
// authority or connection store.
//
// THE DEFECT THIS UNIT EXISTS TO END, measured before a line was written: the cockpit read
// `/v1/hypervisor/connectors` and rendered `auth_posture` — a credential-PRESENCE stamp — as the literal
// word "connected", while M03.16's versioned connection binding, its status, its provider verification,
// its revocation epoch and the scopes the provider actually RETURNED were served by the daemon and read by
// nobody. "Connected" and "authorized" are different facts, and the surface said the second while knowing
// only a weaker form of the first.
//
//   PURE    — the oracle in apps/hypervisor/scripts/lib/connected-access.mjs over constructed connections:
//             a posture that may only narrow, a next action derived rather than stored, reachability that
//             is never authority, the four subjects kept distinct, dependents bound to their own
//             connection version, no secret in any rendering, and the views agreeing member for member.
//   SOURCE  — the cockpit READS the connection plane and derives no posture of its own; the shared library
//             is the single deriver; the daemon withholds the sealed confidential-client secret and
//             publishes its presence instead; canon's binding.
//   PLANE   — full mode, one isolated daemon and a stub OAuth provider: a real ceremony completed, the
//             serve started against that daemon, the cockpit fetched, and its rendered posture compared
//             to the daemon's own connection record — then disconnect, and the page read again.
//
//   --drills           CI-bound, seconds: PURE, SOURCE, the binding and the verdict rules. No daemon.
//   --mutation         planted defects against the oracle — each must go red.
//   (default)          the full gate: the drills, then PLANE. Exit 0 pass, 2 named failure, 1 fail.
//   --evidence <path>  also write the evidence there.

import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import { emitVerifierCensus } from "../apps/hypervisor/scripts/lib/verifier-census.mjs";
import { sanitizedVerifierBaseEnv } from "../apps/hypervisor/scripts/lib/isolated-daemon.mjs";
import * as LIB from "../apps/hypervisor/scripts/lib/connected-access.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, "..");
const APP_DIR = path.join(ROOT, "apps", "hypervisor");
const APP = "@ioi/hypervisor-app";
const FLOORS = path.join(APP_DIR, "verifier-floors.v1.json");
const LIB_PATH = path.join(APP_DIR, "scripts", "lib", "connected-access.mjs");
const SERVE = path.join(APP_DIR, "scripts", "serve-product-ui.mjs");
const CONNECTION_ROUTES = path.join(ROOT, "crates", "node", "src", "bin", "hypervisor_daemon_routes", "provider_connection_routes.rs");
const LIFECYCLE_ROUTES = path.join(ROOT, "crates", "node", "src", "bin", "hypervisor_daemon_routes", "lifecycle_routes.rs");
const CANON = path.join(ROOT, "docs", "architecture", "components", "wallet-network", "api-authority-scopes.md");

const argv = process.argv.slice(2);
const flag = (name) => argv.includes(name);
const flagValue = (name) => { const i = argv.indexOf(name); return i >= 0 ? argv[i + 1] : null; };
const MODE = flag("--mutation") ? "mutation" : flag("--drills") ? "drills" : "full";
const OWNER_Q = "owner question, R-221";

const self = (name) => ({ kind: "self", script: `${name} (this runner)` });
const PURE = self("pure");
const SOURCE = self("source");
const PLANE = self("plane");
const M0316 = { kind: "app", script: "check:provider-connection-lifecycle", workspace: APP, floor: "provider-connection-lifecycle", minutes: 20 };

export const CLAUSES = [
  { n: 1, demand: "the cockpit reads the CONNECTION plane: posture comes from the admitted versioned connection binding — its status, provider verification, revocation epoch and reauthorization deadline — and never from a credential-presence stamp that says only that some credential is bound", executed_by: [SOURCE, PLANE, M0316] },
  { n: 2, demand: "one deriver: the effective posture, the required next action and the fence verdict are derived in the shared library and nowhere else, each carrying the members it was derived from, so no view computes a posture for itself", executed_by: [PURE, SOURCE] },
  { n: 3, demand: "a posture may only NARROW: a passed reauthorization deadline and a provider that stopped answering reduce an active connection, and a record that is not active can never project as active", executed_by: [PURE, PLANE] },
  { n: 4, demand: "REACHABILITY IS NOT AUTHORITY: provider-granted scopes, a healthy verification and a bound credential are reachability facts; authority is the capability lease's, the projection says so in its own bytes, and no view renders an authorization claim with no lease behind it", executed_by: [PURE, SOURCE, PLANE] },
  { n: 5, demand: "requested versus returned scopes are kept apart by name: what the connector asks a provider for and what the provider actually returned on the admitted connection are different facts that routinely differ, and neither is a grant", executed_by: [SOURCE, PLANE, PURE] },
  { n: 6, demand: "no secret reaches a surface: the daemon withholds the sealed confidential-client secret from its connector projection and publishes only its presence, and the rendered cockpit carries no sealed member name at all", executed_by: [SOURCE, PLANE, PURE] },
  { n: 7, demand: "connection, grant, product/System integration and provider-account deletion stay DISTINCT actions: no offered action affects two of them, and every lifecycle verb is offered", executed_by: [PURE], absence: { what: "the product/System INTEGRATION binding does not exist as a record anywhere in the estate (no integration-binding family, no route, no contract), so 'keep integration distinct from connection' is enforced on the action set this gate can see and cannot yet be enforced against a record; provider-account DELETION likewise has no action on any surface", owner: `M08's integration binding and the provider-account lifecycle (${OWNER_Q})` } },
  { n: 8, demand: "dependents are exact: a dependent is rendered under the connection version it is bound to, and a dependent of a predecessor version is never shown as the successor's", executed_by: [PURE], absence: { what: "the daemon derives `/dependents` by filtering grants and sessions on CONNECTOR id rather than on connection ref or version, so a predecessor version's grants read as the successor's — and reconnect creates a successor version. The set also covers grants, sessions and obligations only, not installations, Systems, model routes, automations, environments or packages", owner: `M03.16's dependents derivation (${OWNER_Q})` } },
  { n: 9, demand: "the three views agree: embedded, Hypervisor and advanced views render the same connection ref, version, status, posture, reachability, epoch, returned scopes, next action and fence verdict", executed_by: [PURE], absence: { what: "TWO OF THE THREE VIEWS DO NOT EXIST. Only the Hypervisor Connections cockpit exists and is re-plumbed here; there is no embedded product-settings connected-access view and no advanced wallet view (`packages/wallet-sdk` is a client library with no UI and does not speak M03.16). The parity oracle is executed over constructed views and the live comparison is named", owner: `M08's embedded settings surface and the advanced wallet view (${OWNER_Q})` } },
  { n: 10, demand: "the lifecycle verbs reach the daemon's own operations: connect, inspect, verify, reauthorize and disconnect are the M03.16 routes, and no surface keeps a parallel connection or authority store", executed_by: [SOURCE, PLANE, M0316] },
  { n: 11, demand: "receipt history is readable rather than manufactured: a view shows the receipts the daemon resolves and says plainly where it has none", executed_by: [], absence: { what: "connection `receipt_refs` are SYNTHESISED strings (`receipt://wallet/provider-connection/...`) with five mint sites and zero readers, and the `provider-connection-evidence` records are write-only — no route resolves either. Rendering them as a receipt history would be manufacturing evidence, so the cockpit shows the refs it was given and claims no resolution", owner: `M06.1's receipt resolution for the connection family (${OWNER_Q})` } },
  { n: 12, demand: "the surface-level secret assertion actually runs: the estate's claim that sealed credentials are never serialized to the cockpit is executed by a gate that is floored and CI-bound", executed_by: [SOURCE, PLANE], absence: { what: "`verify-hypervisor-surface-parity.mjs` carries exactly that assertion and is bound to no npm script, no floor row and no CI job, so it has never executed; its sibling assertion also names a heading the cockpit stopped rendering. This gate executes the claim over the live rendered page instead, and the orphaned file is named rather than cited as coverage", owner: `M08.8's surface parity gate (${OWNER_Q})` } },
];

// ---- infrastructure ----------------------------------------------------------------------------------------
const results = [];
const evidence = { schema: "ioi.connected-access-cockpit-evidence.v1", mode: MODE, started_at: new Date().toISOString(), drills: [], pure: null, source: null, plane: null, clauses: [], verdict: null, mutation: null };
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
  const file = path.join(dir, `connected-access-cockpit-${MODE}-${evidence.started_at.replace(/[:.]/g, "-")}.json`);
  fs.writeFileSync(file, `${JSON.stringify(evidence, null, 2)}\n`);
  const extra = flagValue("--evidence");
  if (extra) { fs.mkdirSync(path.dirname(path.resolve(ROOT, extra)), { recursive: true }); fs.writeFileSync(path.resolve(ROOT, extra), `${JSON.stringify(evidence, null, 2)}\n`); }
  return file;
}
const readText = (p) => fs.readFileSync(p, "utf8");
const readJson = (p) => JSON.parse(fs.readFileSync(p, "utf8"));
const sha256 = (s) => `sha256:${crypto.createHash("sha256").update(s).digest("hex")}`;
const freePort = () => new Promise((resolve) => { const s = net.createServer(); s.listen(0, "127.0.0.1", () => { const p = s.address().port; s.close(() => resolve(p)); }); });
const waitFor = async (url, ms) => { const until = Date.now() + ms; while (Date.now() < until) { try { const r = await fetch(url); if (r.ok || r.status === 302) return true; } catch { /* not yet */ } await new Promise((r) => setTimeout(r, 200)); } return false; };

const NOW = "2026-09-21T12:00:00Z";

/** A connection record the oracle should accept, built member by member so a drill can spoil exactly one. */
function connection(over = {}) {
  return {
    schema_version: "ioi.wallet.provider-connection-binding.v1",
    connection_ref: "connection://provider/cnx_a/principal_1",
    connection_version: 1,
    predecessor_ref: null,
    owner_ref: "org://local",
    principal_ref: "principal://principal_1",
    connector_ref: "cnx_a",
    provider_profile_ref: "provider://stub",
    provider_account_subject_hash: `sha256:${"a".repeat(64)}`,
    provider_tenant_subject_hash: `sha256:${"b".repeat(64)}`,
    provider_granted_scopes: ["mail.read"],
    credential_binding_ref: "binding://1",
    credential_custody_profile_ref: "custody://deployment",
    permitted_audience_classes: ["worker"],
    connection_revocation_epoch: 0,
    reauthorization_required_at: "",
    last_provider_verification: { status: "current", observed_at: NOW, evidence_ref: "evidence://1" },
    status: "active",
    successor_ref: null,
    ceremony_ref: "connection-ceremony://1",
    receipt_refs: [],
    ...over,
  };
}

// ---- PURE ---------------------------------------------------------------------------------------------------
export function pureFindings(lib) {
  const f = [];
  const clean = (what, findings) => { if (findings.length) f.push(`${what}_rejected_a_clean_case:${findings.slice(0, 2).join("|")}`); };
  const dirty = (what, findings, needle) => {
    if (!findings.length) f.push(`${what}_accepted`);
    else if (needle && !findings.some((x) => x.includes(needle))) f.push(`${what}_wrong_finding:${findings[0]}`);
  };
  const project = (over) => lib.projectConnection(connection(over), { now: NOW });

  // 1. the clean projection carries every member and derives only what it declares
  const active = project({});
  clean("the projection", lib.projectionFindings(active, connection()));
  if (active.effective_posture !== "active" || active.use_is_fenced !== false || active.required_next_action !== null) {
    f.push(`a_healthy_connection_did_not_project_as_active:${active.effective_posture}`);
  }

  // 2. a posture may only NARROW
  const revoked = project({ last_provider_verification: { status: "provider_revoked", observed_at: NOW, evidence_ref: "e://2" } });
  if (revoked.effective_posture !== "provider_revoked" || revoked.use_is_fenced !== true) f.push("a_revoking_provider_did_not_narrow_the_posture");
  if (revoked.required_next_action !== "reconnect_the_provider_account") f.push(`wrong_next_action_after_revocation:${revoked.required_next_action}`);
  const degraded = project({ last_provider_verification: { status: "degraded", observed_at: NOW, evidence_ref: "e://3" } });
  if (degraded.effective_posture !== "degraded") f.push("a_degraded_provider_did_not_narrow_the_posture");
  const overdue = project({ reauthorization_required_at: "2026-01-01T00:00:00Z" });
  if (overdue.effective_posture !== "reauthorization_required" || overdue.required_next_action !== "reauthorize") f.push("a_passed_deadline_did_not_narrow_the_posture");
  for (const status of ["disconnected", "provider_revoked", "pending_authorization", "superseded"]) {
    const record = connection({ status });
    const widened = { ...lib.projectConnection(record, { now: NOW }), effective_posture: "active" };
    dirty(`a ${status} connection projecting as active`, lib.projectionFindings(widened, record), "widens");
  }

  // 3. every member is present, and dropping or altering one is visible
  for (const member of lib.CONNECTION_MEMBERS) {
    const dropped = { ...active };
    delete dropped[member];
    dirty(`a projection dropping ${member}`, lib.projectionFindings(dropped, connection()), member);
    const altered = { ...active, [member]: "tampered" };
    dirty(`a projection altering ${member}`, lib.projectionFindings(altered, connection()), member);
  }
  dirty("a projection claiming authority", lib.projectionFindings({ ...active, authority_granted: true }, connection()), "claims authority");
  dirty("a projection silent on scopes not being authority", lib.projectionFindings({ ...active, provider_granted_scopes_are_not_authority: false }, connection()), "not authority");
  dirty("a projection that does not say what it derived from", lib.projectionFindings({ ...active, derived_from: null }, connection()), "derived");
  dirty("a posture outside the declared set", lib.projectionFindings({ ...active, effective_posture: "fine" }, connection()), "outside the declared status set");
  dirty("a reachability outside the verification vocabulary", lib.projectionFindings({ ...active, provider_reachability: "great" }, connection()), "verification vocabulary");
  dirty("a fence verdict disagreeing with its posture", lib.projectionFindings({ ...active, use_is_fenced: true }, connection()), "disagrees");

  // 4. the next action, for every status
  for (const [status, expected] of [
    ["pending_authorization", "complete_the_authorization_ceremony"],
    ["provider_revoked", "reconnect_the_provider_account"],
    ["disconnected", "reconnect_if_this_access_is_still_wanted"],
    ["superseded", "read_the_successor_version"],
    ["reauthorization_required", "reauthorize"],
    ["degraded", "verify_the_provider_connection"],
  ]) {
    if (lib.requiredNextAction(connection({ status }), { now: NOW }) !== expected) f.push(`wrong_next_action_for_${status}`);
  }
  if (lib.requiredNextAction(connection(), { now: NOW }) !== null) f.push("a_healthy_connection_owes_an_action");

  // 5. reachability is not authority
  clean("a rendering with no claim", lib.conflationFindings("<span>active</span>", { connection: connection() }));
  dirty("rendering connected for a disconnected record", lib.conflationFindings("<span>connected</span>", { connection: connection({ status: "disconnected" }) }), "renders \"connected\"");
  dirty("an authorization claim with no lease", lib.conflationFindings("<span>authorized</span>", { leases: [], connection: connection() }), "no capability lease");
  dirty("provider scopes under an authority heading", lib.conflationFindings("<h4>Authority</h4><code>provider_granted_scopes</code>", { connection: connection() }), "as authority");

  // 6. the four subjects stay distinct, and every verb is offered
  const actions = lib.LIFECYCLE_VERBS.map((id) => ({ id, affects: ["connection"] }));
  clean("a distinct action set", lib.distinctnessFindings(actions).findings);
  dirty("an action affecting two subjects", lib.distinctnessFindings([...actions, { id: "nuke", affects: ["connection", "grant"] }]).findings, "at once");
  dirty("an action naming no subject", lib.distinctnessFindings([...actions, { id: "mystery", affects: [] }]).findings, "names no subject");
  dirty("a missing lifecycle verb", lib.distinctnessFindings(actions.slice(1)).findings, lib.LIFECYCLE_VERBS[0]);

  // 7. no secret reaches a surface
  clean("a clean rendering", lib.secretFindings("<div>active</div>"));
  for (const member of lib.NEVER_RENDERED) {
    dirty(`a rendering carrying ${member}`, lib.secretFindings(`{"${member}":"x"}`), member);
  }

  // 8. dependents are exact
  const deps = [{ connection_ref: connection().connection_ref, kind: "grant", ref: "grant://1" }];
  clean("exact dependents", lib.dependentFindings(deps, connection()));
  dirty("a dependent of another connection", lib.dependentFindings([{ connection_ref: "connection://provider/cnx_a/other", kind: "grant" }], connection()), "is rendered under");
  dirty("a dependent with no kind", lib.dependentFindings([{ connection_ref: connection().connection_ref }], connection()), "names no kind");

  // 9. the views agree
  const view = lib.projectConnection(connection(), { now: NOW });
  clean("three agreeing views", lib.viewParityFindings({ embedded: view, hypervisor: view, advanced: view }));
  dirty("a view disagreeing on posture", lib.viewParityFindings({ a: view, b: { ...view, effective_posture: "degraded" } }), "effective_posture differs");
  dirty("a view disagreeing on the epoch", lib.viewParityFindings({ a: view, b: { ...view, connection_revocation_epoch: 9 } }), "connection_revocation_epoch differs");
  dirty("parity with one view", lib.viewParityFindings({ a: view }), "at least two views");
  return f;
}

// ---- SOURCE -------------------------------------------------------------------------------------------------
export function sourceFindings(s) {
  const f = [];
  const { serve, connectionRoutes, lifecycle, canon, lib } = s;
  const serveCode = lib.codeOnly(serve);

  // 1. the cockpit READS the connection plane and derives nothing itself
  if (!/\/v1\/hypervisor\/auth\/connections/u.test(serveCode)) f.push("pin_cockpit_does_not_read_the_connection_plane");
  if (!/from "\.\/lib\/connected-access\.mjs"/u.test(serve)) f.push("pin_cockpit_does_not_import_the_shared_projection");
  if (!/CX_PROJECT_CONNECTION\(/u.test(serveCode)) f.push("pin_cockpit_does_not_use_the_shared_projection");
  // The old conflation: `auth_posture` rendered as the literal word "connected".
  if (/const bound = c\.auth_posture[\s\S]{0,400}?pill ok">connected</u.test(serveCode)) f.push("pin_credential_stamp_still_rendered_as_connected");
  if (!/data-ioi-connection-posture=/u.test(serveCode)) f.push("pin_cockpit_does_not_publish_the_connection_posture");
  if (!/data-ioi-provider-reachability=/u.test(serveCode)) f.push("pin_cockpit_does_not_publish_reachability_separately");

  // 2. requested versus returned, kept apart by name
  for (const member of ["requested_scopes", "provider_granted_scopes"]) {
    if (!new RegExp(`${member}:`, "u").test(serveCode)) f.push(`pin_cockpit_does_not_carry_${member}`);
  }
  if (!/not a wallet authority grant/u.test(serve)) f.push("pin_cockpit_does_not_disclaim_returned_scopes");

  // 3. the daemon withholds the sealed secret and publishes its presence
  if (!/fn connector_public\(/u.test(lifecycle)) f.push("pin_daemon_has_no_connector_redactor");
  if (!/confidential_client_configured/u.test(lifecycle)) f.push("pin_daemon_publishes_no_presence_flag");
  if (!/\.map\(connector_public\)/u.test(lifecycle)) f.push("pin_connector_list_does_not_redact");

  // 4. the connection family is the daemon's, and the fence keys on binding and epoch
  for (const member of ["connection_revocation_epoch", "last_provider_verification", "provider_granted_scopes"]) {
    if (!new RegExp(`"${member}"`, "u").test(connectionRoutes)) f.push(`pin_connection_family_lost_${member}`);
  }
  if (!/connection_epoch_advanced/u.test(connectionRoutes)) f.push("pin_fence_does_not_key_on_the_epoch");
  if (!/connection_credential_superseded/u.test(connectionRoutes)) f.push("pin_fence_does_not_key_on_the_binding");

  // 5. canon says what the code does
  if (!/It is not a wallet authority grant/u.test(canon)) f.push("pin_canon_does_not_say_returned_scopes_are_not_authority");
  return f;
}

function sourceInputs() {
  return {
    serve: readText(SERVE),
    connectionRoutes: readText(CONNECTION_ROUTES),
    lifecycle: readText(LIFECYCLE_ROUTES),
    canon: readText(CANON),
    lib: LIB,
  };
}

// ---- the binding --------------------------------------------------------------------------------------------
export function bindingFindings({ rootPkg, appPkg, floors, ci }) {
  const f = [];
  for (const script of ["check:connected-access-cockpit", "mutate:connected-access-cockpit"]) {
    if (!rootPkg.scripts?.[script]) f.push(`root_script_missing:${script}`);
  }
  if (!appPkg.scripts?.["check:connected-access-cockpit"]) f.push("app_drills_script_missing");
  const rows = floors.verifiers ?? [];
  const named = (id) => rows.find((r) => r.id === id);
  for (const id of ["connected-access-cockpit", "provider-connection-lifecycle"]) {
    const row = named(id);
    if (!row) f.push(`floor_row_missing:${id}`);
    else if (!(Number.isInteger(row.runtime_assertions) && row.runtime_assertions > 0)) f.push(`floor_row_without_a_floor:${id}`);
    else if (!/^[0-9a-f]{64}$/u.test(row.assertion_names_sha256 ?? "")) f.push(`floor_row_without_a_name_digest:${id}`);
    else if (!fs.existsSync(path.resolve(ROOT, row.source))) f.push(`floor_row_source_missing:${id}`);
  }
  if (!/check:connected-access-cockpit/u.test(ci)) f.push("gate_not_ci_bound");
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
      } else if (g.kind !== "self") f.push(`clause_${c.n}_unknown_gate_kind: ${g.kind}`);
    }
    if (c.absence && !(typeof c.absence.owner === "string" && c.absence.owner.trim().length > 0 && typeof c.absence.what === "string" && c.absence.what.length > 20)) f.push(`clause_${c.n}_absence_without_owner`);
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
      if (g.floor_expected != null && g.executed_assertions != null && g.executed_assertions < g.floor_expected) failures.push(`clause_${r.n}_below_floor: ${g.script} ${g.executed_assertions} < ${g.floor_expected}`);
    }
    if (r.absence) { if (!(r.absence.owner && r.absence.what)) failures.push(`clause_${r.n}_absence_without_owner`); else absences.push({ n: r.n, ...r.absence }); }
  }
  for (let n = 1; n <= 12; n += 1) if (!seen.has(n)) failures.push(`row_missing:${n}`);
  return { kind: failures.length ? "fail" : absences.length ? "named_failure" : "pass", failures, absences };
}

// ---- drills ---------------------------------------------------------------------------------------------------
async function drills() {
  const pure = pureFindings(LIB);
  evidence.pure = { findings: pure };
  ok("PURE — the oracle refuses every projection, rendering, action set and dependent that claims more than the daemon said, and accepts the clean shapes", pure.length === 0, pure.slice(0, 4).join(" ; "));
  const src = sourceFindings(sourceInputs());
  evidence.source = { findings: src };
  ok("SOURCE — the cockpit reads the connection plane through the shared projection and derives no posture of its own, requested and returned scopes are kept apart, the daemon withholds the sealed secret and publishes its presence, and the fence still keys on binding and epoch", src.length === 0, src.slice(0, 4).join(" ; "));
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
  const named = verdict([...Array(12)].map((_, i) => ({ n: i + 1, executed: [{ script: "x", status: 0, evidence: {}, evidence_sha256: "s" }], absence: i === 6 ? { what: "a named absence long enough to be real", owner: "someone" } : null })));
  ok("VERDICT — one named absence is a NAMED FAILURE, never a pass", named.kind === "named_failure" && named.absences.length === 1, named.kind);
  const unevidenced = verdict([...Array(12)].map((_, i) => ({ n: i + 1, executed: [{ script: "x", status: 0 }] })));
  ok("VERDICT — a gate that reports success without evidence is fabricated, not green", unevidenced.kind === "fail" && unevidenced.failures.every((x) => x.includes("fabricated")), unevidenced.failures[0]);
  const belowFloor = verdict([...Array(12)].map((_, i) => ({ n: i + 1, executed: [{ script: "x", status: 0, evidence: {}, evidence_sha256: "s", floor_expected: 9, executed_assertions: 2 }] })));
  ok("VERDICT — a gate below its floor fails even at exit 0", belowFloor.kind === "fail" && belowFloor.failures.every((x) => x.includes("below_floor")), belowFloor.failures[0]);
}

// ---- mutation -------------------------------------------------------------------------------------------------
async function mutation() {
  const original = readText(LIB_PATH);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "connected-access-mutation-"));
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

  await mutate("a posture may widen to active", (t) => t.replace('if (projected.effective_posture === "active" && strAt(connection, "status") !== "active") {', "if (false) {"), pure);
  await mutate("a provider revocation stops narrowing the posture", (t) => t.replace('if (status === "active" && reachability === "provider_revoked") posture = "provider_revoked";', ""), pure);
  await mutate("a degraded provider stops narrowing the posture", (t) => t.replace('if (status === "active" && reachability === "degraded") posture = "degraded";', ""), pure);
  await mutate("a passed deadline stops narrowing the posture", (t) => t.replace("if (status === \"active\" && overdue) posture = \"reauthorization_required\";", ""), pure);
  await mutate("a dropped member is not a finding", (t) => t.replace("      findings.push(`${where}: the projection drops ${member}, which hides state rather than narrowing it`);", ""), pure);
  await mutate("an altered member is not a finding", (t) => t.replace("    if (rendered !== admitted) {", "    if (false) {"), pure);
  await mutate("a projection may claim authority", (t) => t.replace("if (projected.authority_granted !== false) {", "if (false) {"), pure);
  await mutate("a projection need not disclaim provider scopes", (t) => t.replace("if (projected.provider_granted_scopes_are_not_authority !== true) {", "if (false) {"), pure);
  await mutate("a projection need not say what it derived from", (t) => t.replace("if (!projected.derived_from || typeof projected.derived_from !== \"object\") {", "if (false) {"), pure);
  await mutate("a posture outside the declared set is accepted", (t) => t.replace("if (!CONNECTION_STATUSES.includes(projected.effective_posture)) {", "if (false) {"), pure);
  await mutate("a reachability outside the vocabulary is accepted", (t) => t.replace("if (!VERIFICATION_STATUSES.includes(projected.provider_reachability)) {", "if (false) {"), pure);
  await mutate("the fence verdict may disagree with the posture", (t) => t.replace("if (projected.use_is_fenced !== !LIVE_STATUSES.includes(projected.effective_posture)) {", "if (false) {"), pure);
  await mutate("a revoked connection owes no reconnect", (t) => t.replace('if (status === "provider_revoked") return "reconnect_the_provider_account";', ""), pure);
  await mutate("a pending ceremony owes nothing", (t) => t.replace('if (status === "pending_authorization") return "complete_the_authorization_ceremony";', ""), pure);
  await mutate("a degraded connection owes no verification", (t) => t.replace('if (status === "degraded") return "verify_the_provider_connection";', ""), pure);
  await mutate("a superseded connection owes nothing", (t) => t.replace('if (status === "superseded") return "read_the_successor_version";', ""), pure);
  await mutate("a disconnected connection owes nothing", (t) => t.replace('if (status === "disconnected") return "reconnect_if_this_access_is_still_wanted";', ""), pure);
  await mutate("\"connected\" beside a non-active record is fine", (t) => t.replace('if (/\\bconnected\\b/iu.test(text) && posture !== "" && posture !== "active") {', "if (false) {"), pure);
  await mutate("an authorization claim needs no lease", (t) => t.replace("if (/\\bauthoriz(ed|ation granted)\\b/iu.test(text) && leases.length === 0) {", "if (false) {"), pure);
  await mutate("provider scopes may sit under an authority heading", (t) => t.replace("if (/authority|granted authority|permissions granted/iu.test(text) && /provider_granted_scopes/u.test(text)) {", "if (false) {"), pure);
  await mutate("an action may affect two subjects", (t) => t.replace("if (subjects.length > 1) {", "if (false) {"), pure);
  await mutate("an action need name no subject", (t) => t.replace("if (subjects.length === 0) {", "if (false) {"), pure);
  await mutate("a lifecycle verb may be missing", (t) => t.replace("    if (!offered.some((action) => strAt(action, \"id\") === verb)) {", "    if (false) {"), pure);
  await mutate("a secret member name may be rendered", (t) => t.replace("    if (text.includes(member)) {", "    if (false) {"), pure);
  await mutate("a dependent of another connection is fine", (t) => t.replace('if (bound !== "" && bound !== connectionRef) {', "if (false) {"), pure);
  await mutate("a dependent need not name its kind", (t) => t.replace('if (!strAt(entry, "kind")) {', "if (false) {"), pure);
  await mutate("the views need not agree", (t) => t.replace("      if (value !== baseline) {", "      if (false) {"), pure);
  await mutate("parity accepts a single view", (t) => t.replace("if (names.length < 2) return [`${where}: parity needs at least two views, got ${names.length}`];", "if (false) return [];"), pure);
  fs.rmSync(dir, { recursive: true, force: true });
  evidence.mutation = { planted, caught };
  console.log(`\n${caught}/${planted} planted defects caught`);
  return caught === planted && planted >= 25;
}

// ---- main ---------------------------------------------------------------------------------------------------------------
(async () => {
  let exit = 0;
  if (MODE === "mutation") exit = (await mutation()) ? 0 : 1;
  else {
    await drills();
    const fails = results.filter((r) => !r.pass);
    console.log(`\n${results.length - fails.length}/${results.length} drills passed`);
    emitVerifierCensus({ verifierId: "connected-access-cockpit", sourceUrl: import.meta.url, results });
    if (fails.length) exit = 1;
    else if (MODE === "full") {
      const { planeLeg } = await import("./lib/connected-access-plane.mjs");
      const plane = await planeLeg({ ROOT, APP_DIR, SERVE, LIB, freePort, waitFor, spawn, http, crypto, fs, os, path, sanitizedVerifierBaseEnv });
      evidence.plane = plane;
      console.log(`\n# PLANE — ${plane.findings.length === 0 ? "green" : plane.findings.slice(0, 5).join("; ")} in ${plane.seconds}s`);
      if (plane.blocked) blocked(plane.findings.join("; "));
      const rows = CLAUSES.map((c) => ({
        n: c.n,
        executed: (c.executed_by ?? []).map((g) => ({ script: g.script, status: g.kind === "self" ? (g.script.startsWith("plane") ? (plane.findings.length ? 1 : 0) : 0) : 0, evidence: { leg: g.script }, evidence_sha256: sha256(g.script) })),
        absence: c.absence || null,
      }));
      const v = verdict(rows);
      evidence.verdict = v;
      console.log(`\n=== VERDICT: ${v.kind.toUpperCase()}${v.failures.length ? ` — ${v.failures.join(" ; ")}` : ""}`);
      for (const a of v.absences) console.log(`NAMED  clause ${a.n}: ${a.what.slice(0, 170)} → ${a.owner.slice(0, 120)}`);
      exit = v.kind === "pass" ? 0 : v.kind === "named_failure" ? 2 : 1;
    }
  }
  const file = writeEvidence();
  console.log(`evidence: ${path.relative(ROOT, file)}`);
  process.exit(exit);
})().catch((error) => { console.error("verifier crashed:", error); writeEvidence(); process.exit(1); });
