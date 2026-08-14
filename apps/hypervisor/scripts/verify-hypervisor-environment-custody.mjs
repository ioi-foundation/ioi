#!/usr/bin/env node
// Legacy environment custody verifier — the workspace archive lane gets an OWNER, and the estate's
// one deletion reaches its bytes.
//
// WHAT THIS EXISTS TO CATCH. Next-legs XI closed the unauthenticated half of this lane and filed the
// rest open as its own defect: `POST /v1/hypervisor/snapshots`, `POST /v1/hypervisor/backups` and
// `POST /v1/hypervisor/snapshots/:id/restore` required a session but no OWNER, because an
// environment had none — so every authenticated principal could archive any environment's workspace,
// and the restore handler, which OVERWRITES a workspace, could be pointed at anyone's. Separately the
// W1.5 retention plane's executed deletion destroyed only `managed-backup-material/<state-root>.tar`
// while this lane writes `{snapshots,backups}/<id>/workspace.tar`, so an estate relying on erasure
// had two custody stores and the deletion reached one.
//
// HOW IT CHECKS, and why in this shape:
//   - THREE REAL PRINCIPALS on one live daemon, all holding `org://local`. That precondition is
//     asserted, not assumed, because it is the whole point: `org://local` is the only constructible
//     organization and every principal holds it, so a tenant check isolates NOTHING. Isolation here
//     has to be per-PRINCIPAL or it is not isolation.
//   - EVERY REFUSAL IS PAIRED WITH A COUNT of the durable side effect it must not have produced —
//     material tars on disk, records in the family, admitted operations in the log. A response code
//     proves the answer, never the absence of the act.
//   - ANONYMITY IS BUILT FROM RAW TRANSPORT. A probe made by copying an authenticated client and
//     calling its bound method goes out authenticated and performs the very act it exists to prove
//     refused; that defect shipped once in this estate already.
//   - THE CLOSED WORLD IS DERIVED FROM THE ROUTER, and the classification it derives OVER is itself
//     asserted: every mutating environment-plane route is either censused custody or a NAMED
//     residual this leg does not own, and a stale residual entry is red. A hand-written filter
//     inside a derived census is where coverage silently shrank last time.
//
// WHAT IT DOES NOT PROVE. The environment LIFECYCLE plane (start/stop/archive/delete/exec/workruns)
// is not authorized by this leg and is carried as the named residual list below; those routes still
// resolve no caller. This gate asserts that the residual is exactly that list and no larger.

import { spawn } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import net from "node:net";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";
import { emitVerifierCensus } from "./lib/verifier-census.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const APP = path.resolve(HERE, "..");
const ROOT = path.resolve(APP, "..", "..");

const results = [];
const ok = (name, cond, detail) => results.push({ name, pass: !!cond, detail: detail || "" });
const code = (j) => j?.code ?? j?.error?.code ?? "";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const freePort = () => new Promise((resolve, reject) => {
  const srv = net.createServer();
  srv.listen(0, "127.0.0.1", () => {
    const { port } = srv.address();
    srv.close(() => resolve(port));
  });
  srv.on("error", reject);
});

const waitFor = async (url, ms) => {
  const until = Date.now() + ms;
  while (Date.now() < until) {
    try { const r = await fetch(url); if (r.status < 500) return; } catch { /* not up yet */ }
    await sleep(300);
  }
  throw new Error(`timeout waiting for ${url}`);
};

const daemonBinary = path.resolve(ROOT, process.env.IOI_HYPERVISOR_DAEMON_BINARY ?? "target/debug/hypervisor-daemon");
try {
  fs.accessSync(daemonBinary, fs.constants.X_OK);
} catch {
  console.error(`BLOCKED: daemon binary not executable at ${daemonBinary}`);
  process.exit(2);
}

const scratch = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-env-custody-"));
const dataDir = path.join(scratch, "data");
fs.mkdirSync(dataDir, { recursive: true });

let DAEMON = "";
let daemon = null;
let daemonLog = "";

/** The three principals. `session` is the ONLY thing that makes a request authenticated here. */
const P = { A: { session: "", owner: "", ref: "" }, B: { session: "", owner: "", ref: "" }, C: { session: "", owner: "", ref: "" } };

/**
 * One request. `as: null` means ANONYMOUS and is built from the raw transport — there is no client
 * object to copy, so there is no bound method that could carry a session in by accident.
 */
async function jd(method, p, body, { as = "A" } = {}) {
  const session = as ? P[as].session : "";
  const headers = {};
  if (body !== undefined && body !== null) headers["content-type"] = "application/json";
  if (session) headers.cookie = `ioi_session=${session}`;
  return fetch(`${DAEMON}${p}`, {
    method,
    headers: Object.keys(headers).length ? headers : undefined,
    body: body !== undefined && body !== null ? JSON.stringify(body) : undefined,
  }).then(async (r) => {
    const text = await r.text();
    let j = null;
    try { j = JSON.parse(text); } catch { /* non-json */ }
    return { status: r.status, j, text };
  }).catch((e) => ({ status: 0, j: { transport_error: String(e) }, text: String(e) }));
}

function startDaemon(port) {
  daemon = spawn(daemonBinary, [], {
    cwd: ROOT,
    env: {
      ...process.env,
      IOI_HYPERVISOR_DAEMON_ADDR: `127.0.0.1:${port}`,
      IOI_HYPERVISOR_DATA_DIR: dataDir,
      IOI_HYPERVISOR_MODEL_UPSTREAM: "http://127.0.0.1:1",
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  daemon.stdout.on("data", (c) => { daemonLog = `${daemonLog}${c}`.slice(-64000); });
  daemon.stderr.on("data", (c) => { daemonLog = `${daemonLog}${c}`.slice(-64000); });
}

function stopDaemon() {
  try { daemon?.kill("SIGTERM"); } catch { /* already gone */ }
  daemon = null;
}

function cleanup() {
  stopDaemon();
  try { fs.rmSync(scratch, { recursive: true, force: true }); } catch { /* best effort */ }
}

// ------------------------------------------------------------------- durable-truth readers
// Every one of these reads the FILESYSTEM. Asking the API whether an act happened is asking the
// thing under test to grade itself.

/** Every `workspace.tar` this daemon durably wrote under the legacy capture stores. */
function materialTars() {
  const out = [];
  for (const store of ["snapshots", "backups"]) {
    const root = path.join(dataDir, store);
    let entries = [];
    try { entries = fs.readdirSync(root, { withFileTypes: true }); } catch { continue; }
    for (const entry of entries) {
      if (!entry.isDirectory()) continue;
      const tar = path.join(root, entry.name, "workspace.tar");
      if (fs.existsSync(tar)) out.push(tar);
    }
  }
  return out.sort();
}

/** Every capture RECORD (the admission evidence a deletion must never erase). */
function captureRecords() {
  const out = [];
  for (const store of ["snapshots", "backups"]) {
    const root = path.join(dataDir, store);
    let entries = [];
    try { entries = fs.readdirSync(root); } catch { continue; }
    for (const entry of entries) if (entry.endsWith(".json")) out.push(`${store}/${entry}`);
  }
  return out.sort();
}

/** The daemon's own `safe_id` normalization, mirrored so the collision fixture is provably one. */
const safeId = (id) => id.replace(/[^A-Za-z0-9_-]/gu, "_");

/** One environment record's exact bytes, or "" when absent. Reading the file is the point. */
function environmentRecordBytes(environmentId) {
  const dir = path.join(dataDir, "environments", safeId(environmentId));
  for (const candidate of [path.join(dir, `${safeId(environmentId)}.json`), `${dir}.json`]) {
    try { return fs.readFileSync(candidate, "utf8"); } catch { /* next */ }
  }
  return "";
}

function dispositionRecords() {
  try { return fs.readdirSync(path.join(dataDir, "retention-dispositions")).sort(); } catch { return []; }
}

/** Every byte this daemon durably wrote, including the append-only substrate log. */
function durableBytes() {
  const out = [];
  const walk = (dir) => {
    let entries = [];
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const entry of entries) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) walk(full);
      else { try { out.push(fs.readFileSync(full, "latin1")); } catch { /* gone */ } }
    }
  };
  walk(dataDir);
  return out.join("\n");
}

/** Count admitted operations of one kind across the durable log. */
const countAdmittedOps = (kind) => durableBytes().split(kind).length - 1;

// ------------------------------------------------------------------- the derived closed world

const routerSource = () => fs.readFileSync(path.join(ROOT, "crates/node/src/bin/hypervisor-daemon.rs"), "utf8");

/** Every mutating `/v1/hypervisor/*` route registered to an `environment_routes::` handler. */
const environmentPlaneMutations = () => {
  const found = [];
  for (const chunk of routerSource().split(".route(")) {
    const pathMatch = chunk.match(/^\s*"(\/v1\/hypervisor\/[^"]*)"/u);
    if (!pathMatch) continue;
    const body = chunk.slice(0, chunk.indexOf("\n        )"));
    if (!/environment_routes::/u.test(body)) continue;
    for (const method of ["post", "patch", "put", "delete"]) {
      if (new RegExp(`(^|[^a-z_])${method}\\(`, "u").test(body)) {
        found.push({ method: method.toUpperCase(), path: pathMatch[1] });
      }
    }
  }
  return found;
};

/**
 * The custody lane this leg owns, as EXACT method+path pairs. Every entry must be authorized per
 * PRINCIPAL, and every one is driven anonymously below.
 *
 * EXACT, NOT PREFIXED, and the first revision of this file proves why: a `/v1/hypervisor/environments`
 * PREFIX silently swallowed the lifecycle, port-exposure and pull-request-draft routes into the
 * "custody" set, which would have made the anonymous sweep below claim authorization coverage this
 * leg does not have. A family prefix is a filter, and a filter inside a derived census is exactly
 * where coverage moves without anyone deciding it should.
 */
const CUSTODY_ROUTES = [
  { method: "POST", path: "/v1/hypervisor/environments", reason: "the ownership ROOT — an environment acquires its owner pin here or has none" },
  { method: "POST", path: "/v1/hypervisor/snapshots", reason: "capture: reads an environment's workspace bytes" },
  { method: "POST", path: "/v1/hypervisor/snapshots/:id/restore", reason: "restore: OVERWRITES an environment's workspace" },
  { method: "POST", path: "/v1/hypervisor/backups", reason: "capture: reads an environment's workspace bytes" },
];

/**
 * THE NAMED RESIDUAL, machine-visible rather than prose. These environment-plane mutations are NOT
 * authorized by this leg: they are the environment LIFECYCLE plane, whose ownership model is its own
 * change with its own verifier and its own blast radius. Naming them here means a new
 * environment-plane route cannot land unclassified — it is either censused custody or it is an
 * explicitly named hole — and a stale entry (a route the router no longer carries) is RED, so this
 * list cannot quietly absorb coverage by naming things that do not exist.
 *
 * This list is DERIVED-CHECKED IN BOTH DIRECTIONS below. It was hand-written and wrong on its first
 * revision — seven of its twelve entries named routes that do not exist while five real routes went
 * unclassified — and the two assertions caught every one of them.
 */
const NAMED_UNOWNED = [
  { method: "POST", path: "/v1/hypervisor/projects", reason: "registered to lifecycle_routes::handle_project_create; the projects plane is not this leg" },
  { method: "DELETE", path: "/v1/hypervisor/projects/:id", reason: "project delete — projects plane, unowned" },
  { method: "PATCH", path: "/v1/hypervisor/projects/:id/environment-classes", reason: "OQ-5 saga step 2 — carries its own receipted CAS admission" },
  { method: "POST", path: "/v1/hypervisor/environments/:id/:action", reason: "start|stop|archive|restore|delete|recover — lifecycle, resolves no caller. `delete` REMOVES a workspace, so this is the largest named residual" },
  { method: "POST", path: "/v1/hypervisor/environments/lifecycle/:op", reason: "environment transition read/op — lifecycle, unowned" },
  { method: "POST", path: "/v1/hypervisor/environments/:id/ports/:port/expose", reason: "port exposure — lifecycle, unowned" },
  { method: "POST", path: "/v1/hypervisor/environments/:id/ports/:port/unexpose", reason: "port exposure — lifecycle, unowned" },
  { method: "POST", path: "/v1/hypervisor/environments/:id/pull-request-drafts", reason: "PR draft — lifecycle, unowned" },
  { method: "POST", path: "/v1/hypervisor/workruns", reason: "work-run create — lifecycle, unowned" },
  { method: "POST", path: "/v1/hypervisor/workruns/:id/execute", reason: "work-run execute — lifecycle, unowned" },
  { method: "POST", path: "/v1/hypervisor/exec", reason: "scoped workspace command execution — lifecycle, unowned" },
  { method: "POST", path: "/v1/hypervisor/env-config", reason: "environment config rebuild — lifecycle, unowned" },
  { method: "POST", path: "/v1/hypervisor/maintenance/idle-sweep", reason: "idle sweep — lifecycle, unowned" },
  { method: "POST", path: "/v1/hypervisor/agent-run-transcripts/:id", reason: "agent-run upsert — carries its own deployment-posture refusal" },
];

const routeKey = (r) => `${r.method} ${r.path}`;
const CUSTODY_KEYS = new Set(CUSTODY_ROUTES.map(routeKey));
const isCustody = (route) => CUSTODY_KEYS.has(routeKey(route));

/** A concrete anonymous request for each censused custody endpoint. */
const anonRequestFor = ({ method, path: p }, captureId) => {
  const concrete = p.replace(":id", captureId);
  if (p === "/v1/hypervisor/environments" && method === "POST") return { method, path: concrete, body: { environment_id: "anon-env", spec: {} } };
  if (p === "/v1/hypervisor/snapshots" && method === "POST") return { method, path: concrete, body: { environment_id: "custody_a" } };
  if (p === "/v1/hypervisor/backups" && method === "POST") return { method, path: concrete, body: { environment_id: "custody_a" } };
  return { method, path: concrete, body: {} };
};

// ------------------------------------------------------------------- fixture builders

async function makeMember(letter, email) {
  const created = await jd("POST", "/v1/hypervisor/principals",
    { email, name: `Member ${letter}`, role: "member", password: `env-custody-${letter}-v1` }, { as: "A" });
  const id = created.j?.principal?.principal_id ?? "";
  await jd("POST", `/v1/hypervisor/principals/${id}/tenant-memberships`, {
    tenant_ref: "org://local",
    expected_revision: 0,
    idempotency_key: `env-custody-grant-${letter}-1`,
    reason: "verifier fixture: an ordinary member onboarded into the deployment's only organization",
  }, { as: "A" });
  const login = await jd("POST", "/v1/hypervisor/auth/login", { email, password: `env-custody-${letter}-v1` }, { as: null });
  P[letter].session = login.j?.session_token ?? "";
  const who = (await jd("GET", "/v1/hypervisor/auth/whoami", null, { as: letter })).j || {};
  P[letter].owner = (who.principal?.tenant_refs || []).find((t) => t === "org://local") || "";
  P[letter].ref = who.principal?.principal_ref ?? "";
  return who;
}

/** Create + start one environment through the product routes and return its real workspace root. */
async function provisionEnvironment(letter, environmentId) {
  const created = await jd("POST", "/v1/hypervisor/environments", { environment_id: environmentId, spec: {} }, { as: letter });
  const started = await jd("POST", `/v1/hypervisor/environments/${environmentId}/start`, null, { as: letter });
  return { created, workspace: started.j?.environment?.status?.workspace_root ?? "" };
}

const MARKER = "owned-by-its-own-principal.txt";

async function run() {
  const port = await freePort();
  DAEMON = `http://127.0.0.1:${port}`;
  startDaemon(port);
  await waitFor(`${DAEMON}/healthz`, 30000);

  // ------------------------------------------------------------ principals, and the precondition
  const bootToken = daemonLog.match(/ioi_bootstrap_[a-f0-9]{64}/gu)?.at(-1) ?? null;
  const boot = await jd("POST", "/v1/hypervisor/auth/bootstrap", { token: bootToken, password: "env-custody-a-v1" }, { as: null });
  P.A.session = boot.j?.session_token ?? "";
  const whoA = (await jd("GET", "/v1/hypervisor/auth/whoami", null, { as: "A" })).j || {};
  P.A.owner = (whoA.principal?.tenant_refs || []).find((t) => t === "org://local") || "";
  P.A.ref = whoA.principal?.principal_ref ?? "";
  ok("principal A is a REAL authenticated operator session holding the deployment's org tenant",
    whoA.authenticated === true && P.A.owner === "org://local" && P.A.ref.startsWith("user://"),
    `authenticated ${whoA.authenticated} owner ${P.A.owner} ref ${P.A.ref}`);

  const whoB = await makeMember("B", "env-custody-b@ioi.local");
  const whoC = await makeMember("C", "env-custody-c@ioi.local");
  ok("principal B is a REAL, separately authenticated, non-admin session",
    whoB.authenticated === true && whoB.principal?.role !== "admin" && P.B.session.startsWith("ioi_sess_"),
    `role ${whoB.principal?.role}`);
  ok("principal C is a REAL, separately authenticated, non-admin session",
    whoC.authenticated === true && whoC.principal?.role !== "admin" && P.C.session.startsWith("ioi_sess_"),
    `role ${whoC.principal?.role}`);

  // THE PRECONDITION THAT MAKES EVERY ISOLATION ASSERTION BELOW MEAN SOMETHING. If B and C were not
  // in A's tenant, a tenant check would appear to isolate them and this file would prove nothing.
  ok("PRECONDITION: all three principals hold the SAME org tenant, so a tenant check would isolate NOTHING here",
    P.A.owner === "org://local" && P.B.owner === "org://local" && P.C.owner === "org://local"
      && P.A.ref !== P.B.ref && P.B.ref !== P.C.ref && P.A.ref !== P.C.ref,
    `${P.A.owner} / ${P.B.owner} / ${P.C.owner}`);

  // ------------------------------------------------------------ A owns an environment
  // The id carries an UNDERSCORE deliberately: `safe_id` preserves `-` and rewrites `.`, so only an
  // underscore-bearing id has a colliding alias — and every daemon-minted id is `env_{nanos:x}`, so
  // the default create path always has one. A hyphenated fixture could never produce the failure.
  const ENV_A = "custody_a";
  const { created: createdA, workspace: workspaceA } = await provisionEnvironment("A", ENV_A);
  ok("A's environment was created through the owning route and materialized a REAL workspace inside the daemon's data directory",
    createdA.status === 200 && workspaceA.length > 0 && fs.existsSync(workspaceA)
      && path.resolve(workspaceA).startsWith(path.resolve(dataDir)),
    `status ${createdA.status} ws ${workspaceA}`);

  fs.writeFileSync(path.join(workspaceA, MARKER), "a-owns-this\n");
  ok("PRECONDITION: the subject bytes really are inside the workspace the environment reports",
    fs.readFileSync(path.join(workspaceA, MARKER), "utf8") === "a-owns-this\n", MARKER);

  // The owner pin is DURABLE substrate truth, not a field on the environment record. Count the
  // admitted scope bindings rather than asking the API who owns what.
  ok("creating the environment ADMITTED an owner scope binding to the substrate's own scope stream",
    countAdmittedOps("event_stream.request_resource_scope_bound") >= 1
      && durableBytes().includes("hypervisor-environment"),
    `${countAdmittedOps("event_stream.request_resource_scope_bound")} scope bindings admitted`);

  // ------------------------------------------------------------ CROSS-PRINCIPAL: capture
  let tarsBefore = materialTars();
  const bSnapshot = await jd("POST", "/v1/hypervisor/snapshots", { environment_id: ENV_A }, { as: "B" });
  ok("B cannot SNAPSHOT A's environment — authentication is not authorization, and B is authenticated",
    bSnapshot.status === 403, `status ${bSnapshot.status} code ${code(bSnapshot.j)}`);
  ok("and B's refused snapshot produced NO material on disk — the refusal is the absence of the act, not just its answer",
    materialTars().length === tarsBefore.length,
    `${tarsBefore.length} -> ${materialTars().length} tars`);

  const bBackup = await jd("POST", "/v1/hypervisor/backups", { environment_id: ENV_A }, { as: "B" });
  ok("B cannot BACK UP A's environment either — the two capture routes share one owner gate",
    bBackup.status === 403, `status ${bBackup.status} code ${code(bBackup.j)}`);
  ok("and B's refused backup produced NO material on disk",
    materialTars().length === tarsBefore.length,
    `${tarsBefore.length} -> ${materialTars().length} tars`);

  // ------------------------------------------------------------ A captures its own
  const aSnapshot = await jd("POST", "/v1/hypervisor/snapshots", { environment_id: ENV_A }, { as: "A" });
  const captureId = aSnapshot.j?.snapshot?.snapshot_ref ?? "";
  const captureRoot = aSnapshot.j?.snapshot?.state_root ?? "";
  ok("A CAN snapshot A's own environment, and the capture is addressed by its own coordinate",
    aSnapshot.status === 200 && captureId.startsWith("snap_") && /^sha256:[0-9a-f]{64}$/u.test(captureRoot),
    `status ${aSnapshot.status} ref ${captureId} root ${captureRoot}`);
  ok("the capture wrote exactly ONE new material tar, and it is inside the daemon's own data directory",
    materialTars().length === tarsBefore.length + 1
      && materialTars().every((tar) => path.resolve(tar).startsWith(path.resolve(dataDir))),
    `${tarsBefore.length} -> ${materialTars().length} tars`);
  ok("the capture response does NOT hand back the daemon-local material_path — filesystem layout is not a caller's business",
    aSnapshot.j?.snapshot?.material_path === undefined,
    Object.keys(aSnapshot.j?.snapshot ?? {}).join(","));

  // ------------------------------------------------------------ CROSS-PRINCIPAL: restore
  const markerPath = path.join(workspaceA, MARKER);
  fs.writeFileSync(markerPath, "a-changed-this-after-the-capture\n");
  const bRestore = await jd("POST", `/v1/hypervisor/snapshots/${encodeURIComponent(captureId)}/restore`, null, { as: "B" });
  ok("B cannot RESTORE A's capture — this is the handler that OVERWRITES a workspace",
    bRestore.status === 403, `status ${bRestore.status} code ${code(bRestore.j)}`);
  ok("and A's workspace was NOT overwritten by B's refused restore — the bytes A wrote after the capture are still there",
    fs.readFileSync(markerPath, "utf8") === "a-changed-this-after-the-capture\n",
    fs.readFileSync(markerPath, "utf8").trim());

  // A's own restore works and really does put the captured bytes back.
  const aRestore = await jd("POST", `/v1/hypervisor/snapshots/${encodeURIComponent(captureId)}/restore`, null, { as: "A" });
  ok("A CAN restore A's own capture, and the workspace really returns to the captured content",
    aRestore.status === 200 && aRestore.j?.restored === true
      && fs.readFileSync(markerPath, "utf8") === "a-owns-this\n",
    `status ${aRestore.status} marker ${fs.readFileSync(markerPath, "utf8").trim()}`);

  // ------------------------------------------------------------ the LIST route
  const listB = await jd("GET", "/v1/hypervisor/snapshots", null, { as: "B" });
  ok("B's snapshot list does NOT contain A's capture — listing is derived from the caller's own authorized scope set",
    listB.status === 200 && (listB.j?.snapshots ?? []).every((s) => s.snapshot_ref !== captureId),
    `${(listB.j?.snapshots ?? []).length} rows for B`);
  const listA = await jd("GET", "/v1/hypervisor/snapshots", null, { as: "A" });
  ok("A's snapshot list DOES contain A's capture, and no row leaks the daemon-local material_path",
    listA.status === 200
      && (listA.j?.snapshots ?? []).some((s) => s.snapshot_ref === captureId)
      && (listA.j?.snapshots ?? []).every((s) => s.material_path === undefined),
    `${(listA.j?.snapshots ?? []).length} rows for A`);
  const listAnon = await jd("GET", "/v1/hypervisor/snapshots", null, { as: null });
  ok("and an ANONYMOUS caller gets no list at all — this route answered every capture in the estate, material paths included",
    listAnon.status === 401, `status ${listAnon.status}`);

  // ------------------------------------------------------------ an UNOWNED environment
  // Established by first reference while anonymous, so no owner can be recorded. Fail-closed: an
  // environment nobody owns is an environment nobody may capture — including the admin.
  const UNOWNED_ENV = "custody-unowned";
  const vivified = await jd("GET", `/v1/hypervisor/environments/${UNOWNED_ENV}`, null, { as: null });
  const unownedStart = await jd("POST", `/v1/hypervisor/environments/${UNOWNED_ENV}/start`, null, { as: null });
  const unownedWorkspace = unownedStart.j?.environment?.status?.workspace_root ?? "";
  tarsBefore = materialTars();
  const unownedCapture = await jd("POST", "/v1/hypervisor/snapshots", { environment_id: UNOWNED_ENV }, { as: "A" });
  ok("an environment established by first reference with no resolvable caller carries NO owner, and its capture refuses TYPED — even for the deployment administrator",
    vivified.status === 200 && unownedCapture.status === 403
      && code(unownedCapture.j) === "environment_custody_owner_unbound",
    `vivify ${vivified.status} capture ${unownedCapture.status} code ${code(unownedCapture.j)}`);
  ok("and the refused capture of an unowned environment produced NO material",
    materialTars().length === tarsBefore.length,
    `${tarsBefore.length} -> ${materialTars().length} tars`);
  ok("PRECONDITION: the unowned environment really did MATERIALIZE a workspace, so the seizure below has something to take",
    unownedWorkspace.length > 0 && fs.existsSync(unownedWorkspace),
    unownedWorkspace || "no workspace");

  // A caller cannot take an environment another principal already owns by naming its id at create,
  // and the RECORD is read before and after so "refuses before the record is touched" is proven
  // rather than inferred from a response code.
  const recordPathA = path.join(dataDir, "environments", ENV_A, `${ENV_A}.json`);
  const envRecordBytesBefore = fs.existsSync(recordPathA) ? fs.readFileSync(recordPathA, "utf8") : environmentRecordBytes(ENV_A);
  const squat = await jd("POST", "/v1/hypervisor/environments", { environment_id: ENV_A, spec: {} }, { as: "B" });
  ok("B cannot acquire A's environment by naming its id at create, and A's record is byte-identical afterwards",
    squat.status === 403 && environmentRecordBytes(ENV_A) === envRecordBytesBefore,
    `status ${squat.status} code ${code(squat.j)}`);

  // THE COORDINATE COLLISION. `safe_id` maps every character outside [A-Za-z0-9_-] to `_`, and it is
  // MANY-TO-ONE, so an alias like `custody.a` addresses the SAME record file and the SAME workspace
  // directory as `custody-a`. The first cut of this leg pinned the RAW id while persisting on the
  // safe one, and a review used exactly this to take a fresh pin at the alias, clobber the victim's
  // record, start onto the victim's workspace, capture the victim's bytes and restore over them.
  // A fixture whose id contains no substitutable character could never have produced that failure.
  const ALIAS_A = ENV_A.replace("_", ".");
  ok("PRECONDITION: the alias really does collide — it is a DIFFERENT string that normalizes onto A's own coordinate",
    ALIAS_A !== ENV_A && safeId(ALIAS_A) === ENV_A,
    `${ALIAS_A} -> ${safeId(ALIAS_A)} vs ${ENV_A}`);
  const aliasCreate = await jd("POST", "/v1/hypervisor/environments", { environment_id: ALIAS_A, spec: {} }, { as: "B" });
  ok("B cannot take A's environment through a COLLIDING id — the pin coordinate is the record's coordinate, not the raw string",
    aliasCreate.status === 403, `status ${aliasCreate.status} code ${code(aliasCreate.j)}`);
  ok("and A's record survived the alias create byte-for-byte — the clobber is the harm, not just the pin",
    environmentRecordBytes(ENV_A) === envRecordBytesBefore,
    `${environmentRecordBytes(ENV_A).length} bytes`);
  tarsBefore = materialTars();
  const aliasCapture = await jd("POST", "/v1/hypervisor/snapshots", { environment_id: ALIAS_A }, { as: "B" });
  ok("and B cannot capture A's workspace through the alias either — the custody gate normalizes the same way",
    aliasCapture.status === 403 && materialTars().length === tarsBefore.length,
    `status ${aliasCapture.status} code ${code(aliasCapture.j)}`);

  // SEIZURE OF AN UNOWNED ENVIRONMENT. The first cut let create bind the pin to whoever asked first
  // and then overwrite the record; the second gated adoption on the environment having no
  // materialized workspace, and a review demonstrated that `status.workspace_root` is NULLED by
  // `POST /environments/:id/delete` — a handler that resolves NO CALLER. Two requests, one of them
  // unauthenticated, and the real owner plus the deployment administrator were locked out forever.
  // AN OWNERSHIP DECISION MAY NOT DEPEND ON A MUTABLE FIELD AN UNAUTHENTICATED ROUTE CONTROLS.
  const seizureSecret = path.join(unownedWorkspace, "unowned-content.txt");
  fs.writeFileSync(seizureSecret, "content-that-predates-the-owner-model\n");
  const unownedBytesBefore = environmentRecordBytes(UNOWNED_ENV);
  const seizure = await jd("POST", "/v1/hypervisor/environments", { environment_id: UNOWNED_ENV, spec: {} }, { as: "B" });
  ok("an unowned environment cannot be adopted by whoever asks first — refused typed, not seized",
    seizure.status === 409 && code(seizure.j) === "environment_exists_without_owner",
    `status ${seizure.status} code ${code(seizure.j)}`);
  ok("and the refused seizure neither destroyed the existing record nor left a pin behind",
    environmentRecordBytes(UNOWNED_ENV) === unownedBytesBefore
      && fs.readFileSync(seizureSecret, "utf8") === "content-that-predates-the-owner-model\n",
    `${environmentRecordBytes(UNOWNED_ENV).length} bytes`);
  tarsBefore = materialTars();
  const postSeizureCapture = await jd("POST", "/v1/hypervisor/snapshots", { environment_id: UNOWNED_ENV }, { as: "B" });
  ok("and B still holds no custody of it afterwards — no capture of the pre-existing content is reachable",
    postSeizureCapture.status === 403 && materialTars().length === tarsBefore.length,
    `status ${postSeizureCapture.status} code ${code(postSeizureCapture.j)}`);

  // THE UNAUTHENTICATED CLEAR-AND-ADOPT, driven end to end exactly as the review drove it.
  const wipe = await jd("POST", `/v1/hypervisor/environments/${UNOWNED_ENV}/delete`, null, { as: null });
  ok("PRECONDITION: the unauthenticated delete really does run and really does null the workspace pointer — the field an earlier gate trusted",
    wipe.status === 200 && (wipe.j?.environment?.status?.workspace_root ?? null) === null,
    `status ${wipe.status} workspace_root ${JSON.stringify(wipe.j?.environment?.status?.workspace_root ?? null)}`);
  const seizureAfterWipe = await jd("POST", "/v1/hypervisor/environments", { environment_id: UNOWNED_ENV, spec: {} }, { as: "B" });
  ok("CLEARING THE WORKSPACE WITH AN UNAUTHENTICATED DELETE STILL DOES NOT MAKE IT ADOPTABLE — the decision keys on the pin and the record's existence, neither of which a caller can rewrite",
    seizureAfterWipe.status === 409 && code(seizureAfterWipe.j) === "environment_exists_without_owner",
    `status ${seizureAfterWipe.status} code ${code(seizureAfterWipe.j)}`);

  // AN AUTHENTICATED FIRST REFERENCE MUST STILL ACQUIRE AN OWNER. Removing that binding made every
  // cockpit-vivified environment permanently uncapturable BY EVERY PRINCIPAL — no snapshot, no
  // backup, no restore, no retention duty, forever — which a review demonstrated with the
  // administrator doing the vivify itself. Fail-closed is not the same as unusable.
  const COCKPIT_ENV = "custody_cockpit";
  const cockpitVivify = await jd("GET", `/v1/hypervisor/environments/${COCKPIT_ENV}`, null, { as: "A" });
  const cockpitStart = await jd("POST", `/v1/hypervisor/environments/${COCKPIT_ENV}/start`, null, { as: "A" });
  const cockpitWorkspace = cockpitStart.j?.environment?.status?.workspace_root ?? "";
  ok("PRECONDITION: the cockpit's documented first-reference flow really establishes and starts an environment under an authenticated session",
    cockpitVivify.status === 200 && cockpitStart.status === 200 && cockpitWorkspace.length > 0 && fs.existsSync(cockpitWorkspace),
    `${cockpitVivify.status}/${cockpitStart.status} ws ${cockpitWorkspace}`);
  tarsBefore = materialTars();
  const cockpitCapture = await jd("POST", "/v1/hypervisor/snapshots", { environment_id: COCKPIT_ENV }, { as: "A" });
  ok("an environment established by an AUTHENTICATED first reference acquires its owner and IS capturable — it is not stranded uncapturable by everyone",
    cockpitCapture.status === 200 && materialTars().length === tarsBefore.length + 1,
    `status ${cockpitCapture.status} code ${code(cockpitCapture.j)}`);
  const cockpitCrossPrincipal = await jd("POST", "/v1/hypervisor/snapshots", { environment_id: COCKPIT_ENV }, { as: "B" });
  ok("and that owner is still PER PRINCIPAL — B cannot capture the environment A established by first reference",
    cockpitCrossPrincipal.status === 403, `status ${cockpitCrossPrincipal.status}`);

  // EVERY OWNERSHIP-MINTING SITE, DERIVED FROM THE DAEMON SOURCE. The census below walks ROUTES, and
  // a GET can never appear in it — so a binder call added to a fourth handler would mint ownership
  // somewhere no route assertion looks. This reads the source instead.
  const envRoutesSrc = fs.readFileSync(path.join(ROOT, "crates/node/src/bin/hypervisor_daemon_routes/environment_routes.rs"), "utf8");
  const OWNERSHIP_MINTING_HANDLERS = ["handle_environment_create", "handle_environment_get", "handle_environment_action"];
  const binderCallSites = envRoutesSrc
    .split(/\npub\(crate\) (?:async )?fn |\nfn /u)
    .filter((block) => /bind_environment_owner(_if_resolvable)?\(&st\.data_dir/u.test(block))
    .map((block) => block.split(/[(<]/u)[0].trim());
  ok("EVERY site that mints an environment owner is one of the three ESTABLISHMENT handlers — derived from the daemon source, because a GET mints ownership and no route census can see it",
    binderCallSites.length === OWNERSHIP_MINTING_HANDLERS.length
      && binderCallSites.every((name) => OWNERSHIP_MINTING_HANDLERS.includes(name)),
    binderCallSites.join(",") || "NONE FOUND");

  // A REFUSED CREATE MUST LEAVE NO PIN. Binding before validation let any authenticated principal
  // permanently claim arbitrary ids with cheap 400s — durable scope bindings admitted for requests
  // that were refused, with no unbind to undo them.
  const PIN_LEAK_ENV = "custody-pin-leak";
  const invalidCreate = await jd("POST", "/v1/hypervisor/environments", {
    environment_id: PIN_LEAK_ENV,
    spec: { guardrails: "not-an-object" },
  }, { as: "B" });
  const reclaim = await jd("POST", "/v1/hypervisor/environments", { environment_id: PIN_LEAK_ENV, spec: {} }, { as: "A" });
  ok("a create REFUSED on its spec leaves NO owner pin behind — a refused request must not durably claim the coordinate it was refused at",
    invalidCreate.status >= 400 && invalidCreate.status < 500 && reclaim.status === 200,
    `refused ${invalidCreate.status} then A reclaims ${reclaim.status}`);

  // ------------------------------------------------------------ RETENTION REACH
  // The estate's ONE deletion path. No second delete route is minted here and none is looked for.
  const POLICY = "policy://local/retention/standard";
  const dispositionsBefore = dispositionRecords().length;
  const bDeclare = await jd("POST", "/v1/hypervisor/retention/dispositions", {
    subject_kind: "environment_workspace_capture",
    subject_ref: captureId,
    policy_basis_ref: POLICY,
    owner_ref: P.B.owner,
    idempotency_key: "env-custody-b-declare-1",
  }, { as: "B" });
  ok("B cannot declare a retention duty over A's capture — the subject resolves through the CALLER's own authorized scope set",
    bDeclare.status === 403, `status ${bDeclare.status} code ${code(bDeclare.j)}`);
  ok("and B's refused declaration admitted NO disposition record",
    dispositionRecords().length === dispositionsBefore,
    `${dispositionsBefore} -> ${dispositionRecords().length} dispositions`);

  const unsupported = await jd("POST", "/v1/hypervisor/retention/dispositions", {
    subject_kind: "environment_workspace_tarball",
    subject_ref: captureId,
    policy_basis_ref: POLICY,
    owner_ref: P.A.owner,
    idempotency_key: "env-custody-a-unsupported-1",
  }, { as: "A" });
  ok("an UNLISTED subject kind is refused at declaration, not interpreted — the kind list is closed",
    unsupported.status === 400 && code(unsupported.j) === "retention_subject_kind_unsupported",
    `status ${unsupported.status} code ${code(unsupported.j)}`);

  const declare = await jd("POST", "/v1/hypervisor/retention/dispositions", {
    subject_kind: "environment_workspace_capture",
    subject_ref: captureId,
    policy_basis_ref: POLICY,
    owner_ref: P.A.owner,
    idempotency_key: "env-custody-a-declare-1",
  }, { as: "A" });
  const dispositionId = String(declare.j?.disposition?.disposition_id ?? "").replace("retention-disposition://", "");
  ok("A declares the retention duty over its OWN capture, and the disposition names the exact subject and its payload state root",
    declare.status === 201
      && declare.j?.disposition?.subject?.subject_kind === "environment_workspace_capture"
      && declare.j?.disposition?.subject?.subject_ref === captureId
      && declare.j?.disposition?.subject?.payload_state_root === captureRoot,
    `status ${declare.status} subject ${declare.j?.disposition?.subject?.subject_ref}`);

  // A legal hold blocks the legacy lane's deletion exactly as it blocks the managed lane's.
  const hold = await jd("POST", `/v1/hypervisor/retention/dispositions/${dispositionId}/legal-hold`, {
    hold: true, reason: "verifier: dispute", owner_ref: P.A.owner, idempotency_key: "env-custody-hold-1",
  }, { as: "A" });
  const heldDelete = await jd("POST", `/v1/hypervisor/retention/dispositions/${dispositionId}/delete`, {
    owner_ref: P.A.owner, idempotency_key: "env-custody-delete-held-1",
  }, { as: "A" });
  ok("a LEGAL HOLD blocks the legacy lane's deletion, typed — the second subject kind inherits the plane's boundary, it does not route around it",
    hold.status === 200 && heldDelete.status === 409
      && code(heldDelete.j) === "retention_deletion_blocked_by_legal_hold",
    `hold ${hold.status} delete ${heldDelete.status} code ${code(heldDelete.j)}`);
  ok("and the blocked deletion destroyed NOTHING — the material is still on disk",
    materialTars().some((tar) => tar.includes(captureId)),
    materialTars().join(","));

  await jd("POST", `/v1/hypervisor/retention/dispositions/${dispositionId}/legal-hold`, {
    hold: false, owner_ref: P.A.owner, idempotency_key: "env-custody-release-1",
  }, { as: "A" });

  const destroyedOpsBefore = countAdmittedOps("event_stream.backup_material_destroyed");
  ok("PRECONDITION: no content-destruction fact exists anywhere in this estate before the deletion runs",
    destroyedOpsBefore === 0, `${destroyedOpsBefore} destroyed-material operations`);

  const recordsBefore = captureRecords();
  const execute = await jd("POST", `/v1/hypervisor/retention/dispositions/${dispositionId}/delete`, {
    owner_ref: P.A.owner, idempotency_key: "env-custody-delete-1",
  }, { as: "A" });
  ok("the executed deletion REACHES the legacy store's separate bytes, and says what it destroyed",
    execute.status === 200
      && execute.j?.disposition?.state === "delete_executed"
      && execute.j?.disposition?.deletion?.evidence?.material_present_before === true
      && execute.j?.disposition?.deletion?.evidence?.material_removed === true,
    `status ${execute.status} evidence ${JSON.stringify(execute.j?.disposition?.deletion?.evidence ?? {})}`);
  ok("and the tar really is GONE from the filesystem — the evidence is not the daemon's opinion of itself",
    !materialTars().some((tar) => tar.includes(captureId)),
    materialTars().join(",") || "no material tars remain");
  ok("while the capture RECORD survives as admission evidence — deletion removes content, never the proof a deletion happened",
    captureRecords().length === recordsBefore.length
      && captureRecords().some((record) => record.includes(captureId)),
    captureRecords().join(","));

  // ------------------------------------------------------------ ONE DESTRUCTION FACT, BOTH LANES
  ok("the legacy deletion admitted the MANAGED lane's own destroyed-material operation — one estate-wide fact, not a second stream this lane could be resurrected around",
    countAdmittedOps("event_stream.backup_material_destroyed") === destroyedOpsBefore + 1,
    `${destroyedOpsBefore} -> ${countAdmittedOps("event_stream.backup_material_destroyed")}`);
  ok("and the tombstone that names the RECORD was admitted too, head-preserving rather than removing it",
    countAdmittedOps("event_stream.environment_capture_lifecycle_pruned") === 1,
    `${countAdmittedOps("event_stream.environment_capture_lifecycle_pruned")} prune operations`);

  const deletedRestore = await jd("POST", `/v1/hypervisor/snapshots/${encodeURIComponent(captureId)}/restore`, null, { as: "A" });
  ok("restoring a deleted capture answers the DELETION, not a lost-disk observable — that distinction is what makes an executed deletion auditable",
    deletedRestore.status === 410 && code(deletedRestore.j) === "environment_capture_tombstoned",
    `status ${deletedRestore.status} code ${code(deletedRestore.j)}`);

  // RE-CAPTURE OVER A DESTRUCTION. The workspace still holds the exact captured bytes (A restored
  // them above), so an ordinary second capture would land on the content an owner ordered destroyed.
  tarsBefore = materialTars();
  const recapture = await jd("POST", "/v1/hypervisor/snapshots", { environment_id: ENV_A }, { as: "A" });
  ok("re-capturing the destroyed CONTENT refuses under the managed lane's own code — the read side of the shared fact, so a fresh coordinate is not a way back in",
    recapture.status === 410 && code(recapture.j) === "managed_backup_material_destroyed",
    `status ${recapture.status} code ${code(recapture.j)}`);
  ok("and the refused re-capture wrote NO new material — it refuses before a byte is written, not after",
    materialTars().length === tarsBefore.length,
    `${tarsBefore.length} -> ${materialTars().length} tars`);

  // THE ALIAS COORDINATE, END TO END. `safe_id` is many-to-one, so `snap.<hex>` normalizes onto the
  // daemon-minted `snap_<hex>`. A review demonstrated that normalizing only at the scope-authorize
  // seam left the lifecycle stream, the retention subject and the tombstone reading the RAW spelling:
  // a duty declared at an alias was admitted and could then never be executed, while its own refusal
  // said "retry to converge". A MIXED CONVENTION IS THE SAME DEFECT IN A NEW PLACE.
  const ALIAS_CAPTURE = captureId.replace("_", ".");
  ok("PRECONDITION: the capture alias really collides — a different string normalizing onto the minted coordinate",
    ALIAS_CAPTURE !== captureId && safeId(ALIAS_CAPTURE) === captureId,
    `${ALIAS_CAPTURE} -> ${safeId(ALIAS_CAPTURE)}`);
  const aliasRestore = await jd("POST", `/v1/hypervisor/snapshots/${encodeURIComponent(ALIAS_CAPTURE)}/restore`, null, { as: "A" });
  ok("restoring through the ALIAS answers the same tombstone by NAME — the refusal that makes a deletion auditable is not bypassable by spelling",
    aliasRestore.status === 410 && code(aliasRestore.j) === "environment_capture_tombstoned",
    `status ${aliasRestore.status} code ${code(aliasRestore.j)}`);

  // AND A RETENTION DUTY DECLARED AT THE ALIAS MUST BE EXECUTABLE. This is the half that failed: the
  // scope authorized (it normalizes), the duty was admitted at the caller's spelling, and every
  // execute answered `retention_deletion_subject_tombstone_failed` — "NOTHING was destroyed — retry
  // to converge" — forever. An erasure duty that can be declared and never discharged is worse than
  // one that refuses at declaration.
  fs.writeFileSync(path.join(workspaceA, "second-capture.txt"), "distinct-content-for-a-second-state-root\n");
  const second = await jd("POST", "/v1/hypervisor/snapshots", { environment_id: ENV_A }, { as: "A" });
  const secondId = second.j?.snapshot?.snapshot_ref ?? "";
  const secondAlias = secondId.replace("_", ".");
  ok("PRECONDITION: a SECOND capture over distinct content lands its own coordinate and its own material",
    second.status === 200 && secondId.startsWith("snap_") && materialTars().some((tar) => tar.includes(secondId)),
    `status ${second.status} ref ${secondId}`);
  const aliasDeclare = await jd("POST", "/v1/hypervisor/retention/dispositions", {
    subject_kind: "environment_workspace_capture",
    subject_ref: secondAlias,
    policy_basis_ref: POLICY,
    owner_ref: P.A.owner,
    idempotency_key: "env-custody-alias-declare-1",
  }, { as: "A" });
  const aliasDispositionId = String(aliasDeclare.j?.disposition?.disposition_id ?? "").replace("retention-disposition://", "");
  ok("a duty declared at the ALIAS stores the CANONICAL subject — the caller's spelling does not travel past the resolver",
    aliasDeclare.status === 201 && aliasDeclare.j?.disposition?.subject?.subject_ref === secondId,
    `status ${aliasDeclare.status} subject ${aliasDeclare.j?.disposition?.subject?.subject_ref}`);
  const aliasExecute = await jd("POST", `/v1/hypervisor/retention/dispositions/${aliasDispositionId}/delete`, {
    owner_ref: P.A.owner, idempotency_key: "env-custody-alias-delete-1",
  }, { as: "A" });
  ok("and it EXECUTES — the duty discharges instead of refusing forever with an instruction to retry",
    aliasExecute.status === 200
      && aliasExecute.j?.disposition?.deletion?.evidence?.material_removed === true
      && !materialTars().some((tar) => tar.includes(secondId)),
    `status ${aliasExecute.status} code ${code(aliasExecute.j)}`);

  // ------------------------------------------------------------ RESTART SURVIVAL
  const pidBefore = daemon?.pid ?? 0;
  stopDaemon();
  await sleep(600);
  startDaemon(port);
  await waitFor(`${DAEMON}/healthz`, 30000);
  ok("PRECONDITION: this really is a NEW PROCESS over the SAME data directory — a restart proof against the same process proves nothing",
    pidBefore > 0 && (daemon?.pid ?? 0) > 0 && daemon.pid !== pidBefore,
    `pid ${pidBefore} -> ${daemon?.pid}`);
  ok("PRECONDITION: and the deleted bytes are still absent from disk while the capture record is still present, before anything is asked of the API",
    !materialTars().some((tar) => tar.includes(captureId))
      && captureRecords().some((record) => record.includes(captureId)),
    `${materialTars().length} tars, ${captureRecords().length} records`);
  const afterRestart = await jd("POST", `/v1/hypervisor/snapshots/${encodeURIComponent(captureId)}/restore`, null, { as: "A" });
  ok("ACROSS A DAEMON RESTART the deletion still stands and the capture is still not restore material",
    afterRestart.status === 410 && code(afterRestart.j) === "environment_capture_tombstoned",
    `status ${afterRestart.status} code ${code(afterRestart.j)}`);
  const isolationAfterRestart = await jd("POST", "/v1/hypervisor/snapshots", { environment_id: ENV_A }, { as: "B" });
  ok("and the per-principal owner pin survives the restart — B still cannot capture A's environment",
    isolationAfterRestart.status === 403, `status ${isolationAfterRestart.status}`);

  // ------------------------------------------------------------ the derived closed world
  const inventory = environmentPlaneMutations();
  const key = routeKey;
  const census = inventory.filter(isCustody);
  const residual = inventory.filter((route) => !isCustody(route));
  const namedKeys = new Set(NAMED_UNOWNED.map(key));
  const unclassified = residual.filter((route) => !namedKeys.has(key(route)));
  ok("EVERY mutating environment-plane route is either censused custody or a NAMED residual — a new route cannot land unclassified",
    inventory.length > 0 && unclassified.length === 0,
    unclassified.map(key).join(", ") || `${census.length} custody of ${inventory.length} mutations`);
  const inventoryKeys = new Set(inventory.map(key));
  const staleEntries = [...NAMED_UNOWNED, ...CUSTODY_ROUTES].filter((entry) => !inventoryKeys.has(key(entry)));
  ok("and NEITHER list carries a stale entry — a classification that can name routes the router does not have is a classification that can absorb coverage",
    staleEntries.length === 0, staleEntries.map(key).join(", ") || `${NAMED_UNOWNED.length} named residuals + ${CUSTODY_ROUTES.length} custody routes, all live`);
  ok("the censused custody lane is exactly the four routes this leg authorizes, and the two lists PARTITION the inventory with no overlap",
    census.length === CUSTODY_ROUTES.length
      && CUSTODY_ROUTES.every((route) => inventoryKeys.has(key(route)))
      && CUSTODY_ROUTES.every((route) => !namedKeys.has(key(route)))
      && census.length + residual.length === inventory.length,
    `${census.length} custody + ${residual.length} residual = ${inventory.length} inventory`);

  const anonymousRefusals = [];
  for (const endpoint of census) {
    const request = anonRequestFor(endpoint, captureId);
    const response = await jd(request.method, request.path, request.body, { as: null });
    anonymousRefusals.push({ endpoint: key(endpoint), status: response.status });
  }
  const unauthenticatedDoors = anonymousRefusals.filter((r) => r.status !== 401);
  ok("EVERY censused custody mutation refuses an ANONYMOUS caller, and the probe is built from raw transport rather than a copied client",
    unauthenticatedDoors.length === 0,
    unauthenticatedDoors.map((d) => `${d.endpoint} -> ${d.status}`).join(", ") || `${anonymousRefusals.length} endpoints`);
  ok("and none of those anonymous attempts produced a capture — the refusals are the absence of the acts",
    materialTars().length === tarsBefore.length,
    `${tarsBefore.length} -> ${materialTars().length} tars`);

  const fails = results.filter((r) => !r.pass);
  for (const r of results) console.log(`${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? ` — ${r.detail}` : ""}`);
  console.log(`\n${results.length - fails.length}/${results.length} passed`);
  emitVerifierCensus({ verifierId: "environment-custody", sourceUrl: import.meta.url, results });
  cleanup();
  process.exit(fails.length ? 1 : 0);
}

run().catch((error) => {
  // Print what was actually observed before the throw, so a broken fixture and a caught defect are
  // distinguishable from outside. NO CENSUS IS EMITTED HERE: `check:verifier-floors` reads a missing
  // census as RED, which is the correct reading of a run that did not finish — emitting a short one
  // would hand the floor a smaller number to compare against.
  for (const r of results) console.log(`${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? ` — ${r.detail}` : ""}`);
  console.log(`\n${results.filter((r) => r.pass).length}/${results.length} passed BEFORE THE RUN DIED (incomplete — no census emitted)`);
  console.error(`FAIL environment-custody — ${error?.stack || error}`);
  cleanup();
  process.exit(1);
});
