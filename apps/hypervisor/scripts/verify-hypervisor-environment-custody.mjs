#!/usr/bin/env node
// Environment owner + capture custody verifier — environment authority is pinned before durable
// coordinates exist; captures keep their own immutable derived pin; retention deletion reaches the
// material bytes while preserving evidence.
//
// WHAT THIS EXISTS TO CATCH. A session without an environment-owner pin once let every principal in
// `org://local` capture or overwrite any workspace. The same class appeared through lifecycle,
// workrun, terminal, AgentOps, editor, preview and managed-backup handles. Refusals here are paired
// with durable side-effect counts; the source census separately derives the closed world across
// router modules and transitive helper calls.
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
//   - THE CLOSED WORLD IS DERIVED FROM ROUTER SOURCE and a transitive Rust function call graph.
//     Every registered handler resolves, every environment/workspace sink is positively classified,
//     and any unclassified reach is red. The three exact capture mutations are then driven live.
//
// Legacy captures created before ownership pins remain evidence-only: invisible to owner lists,
// unrestorable, and ineligible for a newly invented retention authority.

import { spawn } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import net from "node:net";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";
import { emitVerifierCensus } from "./lib/verifier-census.mjs";
import { deriveEnvironmentOwnerCensus } from "./lib/environment-owner-source-census.mjs";

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

/**
 * The live custody probes are exact method+path pairs. This is not the closed-world inventory; the
 * source call-graph census derives that above every module. These three are the byte-copy mutations
 * this gate can pair with exact tar counts.
 */
const CUSTODY_ROUTES = [
  { method: "POST", path: "/v1/hypervisor/snapshots", reason: "capture: reads an environment's workspace bytes" },
  { method: "POST", path: "/v1/hypervisor/snapshots/:id/restore", reason: "restore: OVERWRITES an environment's workspace" },
  { method: "POST", path: "/v1/hypervisor/backups", reason: "capture: reads an environment's workspace bytes" },
];

const routeKey = (r) => `${r.method} ${r.path}`;
const CUSTODY_KEYS = new Set(CUSTODY_ROUTES.map(routeKey));

/** A concrete anonymous request for each censused custody endpoint. */
const anonRequestFor = ({ method, path: p }, captureId) => {
  const concrete = p.replace(":id", captureId);
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
async function provisionEnvironment(letter) {
  const created = await jd("POST", "/v1/hypervisor/environments", { spec: {} }, { as: letter });
  const environmentId = created.j?.environment?.id ?? "";
  const started = environmentId
    ? await jd("POST", `/v1/hypervisor/environments/${environmentId}/start`, null, { as: letter })
    : { status: 0, j: {} };
  return { created, environmentId, workspace: started.j?.environment?.status?.workspace_root ?? "" };
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
  const { created: createdA, environmentId: ENV_A, workspace: workspaceA } = await provisionEnvironment("A");
  ok("A's environment was created through the owning route and materialized a REAL workspace inside the daemon's data directory",
    createdA.status === 200 && workspaceA.length > 0 && fs.existsSync(workspaceA)
      && path.resolve(workspaceA).startsWith(path.resolve(dataDir)),
    `status ${createdA.status} ws ${workspaceA}`);

  ok("PRECONDITION: the workspace root is an ABSOLUTE path inside the daemon's data directory — a fixture write against an empty root lands in the process CWD, where cleanup never reaches it",
    path.isAbsolute(workspaceA) && path.resolve(workspaceA).startsWith(path.resolve(dataDir)),
    workspaceA || "(empty)");
  if (!path.isAbsolute(workspaceA) || !path.resolve(workspaceA).startsWith(path.resolve(dataDir))) {
    throw new Error(`unsafe fixture workspace for A: ${workspaceA || "(empty)"}`);
  }
  fs.writeFileSync(path.join(workspaceA, MARKER), "a-owns-this\n");
  ok("PRECONDITION: the subject bytes really are inside the workspace the environment reports",
    fs.readFileSync(path.join(workspaceA, MARKER), "utf8") === "a-owns-this\n", MARKER);

  // ------------------------------------------------------------ THE ENVIRONMENT OWNER BOUNDARY
  const envRoutesSrc = fs.readFileSync(path.join(ROOT, "crates/node/src/bin/hypervisor_daemon_routes/environment_routes.rs"), "utf8");
  ok("the environment owner model is wired at the only creation seam: daemon-minted id, immutable substrate pin, and owner authorization helpers are all present",
    /ENVIRONMENT_SCOPE_KIND:\s*&str\s*=\s*"hypervisor-environment"/u.test(envRoutesSrc)
      && /bind_request_resource_scope/u.test(envRoutesSrc)
      && /authorize_environment_owner/u.test(envRoutesSrc),
    "daemon mint + substrate pin + authorization helper");

  const aSnapshot = await jd("POST", "/v1/hypervisor/snapshots", { environment_id: ENV_A }, { as: "A" });
  const captureId = aSnapshot.j?.snapshot?.snapshot_ref ?? "";
  const captureRoot = aSnapshot.j?.snapshot?.state_root ?? "";
  let tarsBefore = materialTars();
  const bCapturesAEnv = await jd("POST", "/v1/hypervisor/snapshots", { environment_id: ENV_A }, { as: "B" });
  ok("an authenticated same-tenant NON-OWNER cannot capture another principal's environment, and the refusal writes no material",
    bCapturesAEnv.status === 403 && materialTars().length === tarsBefore.length,
    `status ${bCapturesAEnv.status} tars ${tarsBefore.length} -> ${materialTars().length}`);

  // The destructive half: even knowing A's capture id gives B neither capture authority nor
  // destination-environment authority.
  fs.writeFileSync(path.join(workspaceA, "a-work-after-b-captured.txt"), "work A did after B captured\n");
  const foreignRestore = await jd("POST", `/v1/hypervisor/snapshots/${encodeURIComponent(captureId)}/restore`, null, { as: "B" });
  ok("an authenticated same-tenant NON-OWNER cannot restore A's capture over A's environment, and A's later bytes remain",
    foreignRestore.status === 403
      && fs.existsSync(path.join(workspaceA, "a-work-after-b-captured.txt")),
    `status ${foreignRestore.status} A's later work still present: ${fs.existsSync(path.join(workspaceA, "a-work-after-b-captured.txt"))}`);

  // ------------------------------------------------------------ WHAT IT DOES OWN: the capture
  const { environmentId: ENV_B, workspace: workspaceB } = await provisionEnvironment("B");
  if (!path.isAbsolute(workspaceB) || !path.resolve(workspaceB).startsWith(path.resolve(dataDir))) {
    throw new Error(`unsafe fixture workspace for B: ${workspaceB || "(empty)"}`);
  }
  fs.writeFileSync(path.join(workspaceB, "b-owned.txt"), "b owns this\n");
  const bOwnSnapshot = await jd("POST", "/v1/hypervisor/snapshots", { environment_id: ENV_B }, { as: "B" });
  const foreignCapture = bOwnSnapshot.j?.snapshot?.snapshot_ref ?? "";
  const aReadsForeign = await jd("POST", `/v1/hypervisor/snapshots/${encodeURIComponent(foreignCapture)}/restore`, null, { as: "A" });
  ok("a CAPTURE is independently owned by whoever took it — A cannot restore B's capture of B's environment",
    bOwnSnapshot.status === 200 && foreignCapture.startsWith("snap_") && aReadsForeign.status === 403,
    `capture ${bOwnSnapshot.status} restore ${aReadsForeign.status} code ${code(aReadsForeign.j)}`);

  // The capture RECORD must name the canonical environment, not the caller's spelling: `safe_id` is
  // many-to-one, so storing the raw id planted a record whose `environment_ref` disagreed with the
  // workspace the material actually came from.
  const aliasEnv = ENV_A.replace("_", ".");
  tarsBefore = materialTars();
  const aliasCapture = await jd("POST", "/v1/hypervisor/snapshots", { environment_id: aliasEnv }, { as: "A" });
  ok("a non-canonical environment alias is REFUSED rather than folded onto the owner's coordinate, with no capture side effect",
    aliasCapture.status === 400 && materialTars().length === tarsBefore.length,
    `requested ${aliasEnv} status ${aliasCapture.status} tars ${tarsBefore.length} -> ${materialTars().length}`);

  ok("A's own capture is admitted and addressed by its own coordinate",
    aSnapshot.status === 200 && captureId.startsWith("snap_") && /^sha256:[0-9a-f]{64}$/u.test(captureRoot),
    `status ${aSnapshot.status} ref ${captureId}`);
  ok("the capture response does NOT hand back the daemon-local material_path — filesystem layout is not a caller's business",
    aSnapshot.j?.snapshot?.material_path === undefined,
    Object.keys(aSnapshot.j?.snapshot ?? {}).join(","));

  const bRestore = await jd("POST", `/v1/hypervisor/snapshots/${encodeURIComponent(captureId)}/restore`, null, { as: "B" });
  ok("B cannot RESTORE A's capture — the handler that OVERWRITES a workspace resolves the capture through the caller's OWN scope set",
    bRestore.status === 403, `status ${bRestore.status} code ${code(bRestore.j)}`);
  const markerPath = path.join(workspaceA, MARKER);
  fs.writeFileSync(markerPath, "a-changed-this-after-the-capture\n");
  const bRestoreAgain = await jd("POST", `/v1/hypervisor/snapshots/${encodeURIComponent(captureId)}/restore`, null, { as: "B" });
  ok("and A's workspace was NOT overwritten by B's refused restore — the bytes A wrote after the capture are still there",
    bRestoreAgain.status === 403 && fs.readFileSync(markerPath, "utf8") === "a-changed-this-after-the-capture\n",
    fs.readFileSync(markerPath, "utf8").trim());
  const aRestore = await jd("POST", `/v1/hypervisor/snapshots/${encodeURIComponent(captureId)}/restore`, null, { as: "A" });
  ok("A CAN restore A's own capture, and the workspace really returns to the captured content",
    aRestore.status === 200 && aRestore.j?.restored === true
      && fs.readFileSync(markerPath, "utf8") === "a-owns-this\n",
    `status ${aRestore.status}`);

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

  // THE COORDINATE COLLISION, on the coordinate this lane actually pins. `safe_id` is MANY-TO-ONE,
  // and normalizing at one seam while carrying the raw spelling onward is the defect this leg
  // shipped once: a retention duty declared at an alias was ADMITTED and could never be executed.
  // NO CROSS-PRINCIPAL ALIAS ASSERTION HERE, deliberately. B holds no scope at the exact spelling
  // either, so a 403 on the alias would be indistinguishable from a 403 on anything at all — the
  // same refusal answers a nonexistent id and an empty ref. The coordinate rule is proven on the
  // OWNER side, below and after the deletion, where the alias must resolve to the same object.

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

  // THE REACH IS NOT RETROACTIVE, and canon says so — so it is gated here rather than asserted only
  // in prose. A capture written before this leg carries no owner scope pin, and every path resolves
  // its subject through the caller's OWN authorized scope set, so such a capture cannot be listed,
  // restored, or named as a retention subject BY ANYONE. Its bytes have no route in the estate that
  // can destroy them. The record is planted directly because that is exactly what the PREVIOUS BUILD
  // left on disk — this is the one fixture whose whole point is being what the product no longer
  // produces.
  const PRE_LEG = "snap_prelegacy0000";
  const preLegDir = path.join(dataDir, "snapshots", PRE_LEG);
  fs.mkdirSync(preLegDir, { recursive: true });
  const preLegMaterial = Buffer.from("pre-leg capture bytes\n", "utf8");
  fs.writeFileSync(path.join(preLegDir, "workspace.tar"), preLegMaterial);
  // BYTE-FAITHFUL TO WHAT THE PREVIOUS BUILD WROTE, because a fixture that is only roughly the
  // product's shape is the scar this estate already carries: the state root is the real digest of
  // this material, the byte count is its real length, and `material_ref` is present as
  // `capture_workspace` has written it SINCE 3ae3f6810 (2026-07-29) — not since always; that
  // commit's parent wrote an eight-key record. So this fixture is faithful to the IMMEDIATELY
  // PRECEDING build, and a capture older than that date has a strictly smaller field set. The
  // residual does not turn on the field set either way: its mechanism is the ABSENT SCOPE PIN,
  // which no build in this store's history ever minted. That is the ONE thing under test here.
  const preLegRoot = `sha256:${crypto.createHash("sha256").update(preLegMaterial).digest("hex")}`;
  fs.writeFileSync(path.join(dataDir, "snapshots", `${PRE_LEG}.json`), JSON.stringify({
    schema_version: "ioi.hypervisor.environment-snapshot.v1", snapshot_ref: PRE_LEG, kind: "snapshot",
    environment_ref: ENV_A, state_root: preLegRoot,
    material_ref: `local-cas://sha256/${preLegRoot.slice("sha256:".length)}`,
    material_path: path.join(preLegDir, "workspace.tar"), bytes: preLegMaterial.length,
    created_at: new Date().toISOString(),
  }, null, 2));
  const preLegShape = JSON.parse(fs.readFileSync(path.join(dataDir, "snapshots", `${PRE_LEG}.json`), "utf8"));
  // WHY ANY CAPTURE RECORD SERVES AS THE EXEMPLAR: THE RETENTION PLANE NEVER REWRITES ONE. Executed
  // deletion removes exactly one tar — `capture_material_path(kind, subject_ref)` — and writes the
  // tombstone to the lifecycle and destroyed-material STREAMS; no path in the estate edits a capture
  // record, which is what "admission evidence survives the content" means here. So the record read
  // below carries the field set the current build writes regardless of what happened to its bytes.
  //
  // AN EARLIER VERSION OF THIS COMMENT JUSTIFIED THE CHOICE WITH TWO CLAIMS, AND A REVIEW FALSIFIED
  // BOTH — recorded rather than quietly deleted, because a stated reason that has gone false is the
  // defect this whole leg keeps paying for. It said `foreignCapture` is a LIVE-content capture: it
  // is not. B captures A's workspace, restores it, and A's later captures are taken over identical
  // content, so all three share one `state_root` — which is exactly why the destroyed-content
  // refusal elsewhere in this journey works. And it said `foreignCapture` is "still restorable":
  // it is not, for anyone including its owner. `refuse_if_capture_deleted` falls through to
  // `refuse_if_material_destroyed_public(data_dir, state_root)`, which is CONTENT-keyed and
  // estate-wide, so it answers 410 `managed_backup_material_destroyed`.
  //
  // The hazard that comment feared — a later cut redacting `material_path`/`material_ref`/`bytes`
  // from a record whose content is gone — is real, applies to EVERY capture here equally, and is
  // already handled: under the set comparison below a shrunken exemplar is a length mismatch and
  // goes RED loudly. It is the SUBSET check this replaced that would have stayed green.
  const liveShape = JSON.parse(fs.readFileSync(path.join(dataDir, "snapshots", `${foreignCapture}.json`), "utf8"));
  const preLegKeys = Object.keys(preLegShape).sort();
  const liveKeys = Object.keys(liveShape).sort();
  // SET EQUALITY, BOTH DIRECTIONS. A subset check in the direction live ⊆ planted certifies a
  // fixture carrying fields NO build ever wrote — including one spelled like an owner pin — while
  // the label claims the SAME fields. That is this run's own label-overclaim scar, so the check is
  // now what the label says.
  ok("PRECONDITION: the planted capture's field set is EXACTLY the field set a capture the current build just produced carries — a fixture that is only roughly the product's shape proves only roughly what it claims",
    preLegKeys.length === liveKeys.length && preLegKeys.every((key, i) => key === liveKeys[i]),
    `planted [${preLegKeys.join(",")}] vs live [${liveKeys.join(",")}]`);
  // AND ITS DIGEST AND LENGTH ARE DERIVED, NOT TYPED. These two conjuncts read back the material
  // this fixture itself wrote, so no daemon fact is under test here and the label does not claim
  // one. What they DO catch is the defect they replaced: a hand-typed `sha256:0…0` and a guessed
  // byte count, which made the "pre-leg capture" a shape the product could never have produced.
  ok("and the planted capture's state root and byte count are DERIVED from its own material rather than hand-typed constants — the fixture-fidelity defect this replaced, ratcheted shut",
    preLegShape.state_root === `sha256:${crypto.createHash("sha256").update(fs.readFileSync(path.join(preLegDir, "workspace.tar"))).digest("hex")}`
      && preLegShape.bytes === fs.statSync(path.join(preLegDir, "workspace.tar")).size,
    `${preLegShape.state_root} / ${preLegShape.bytes} bytes`);
  const preLegList = await jd("GET", "/v1/hypervisor/snapshots", null, { as: "A" });
  ok("a pre-leg capture is INVISIBLE to listing, for the deployment administrator as much as anyone",
    preLegList.status === 200 && (preLegList.j?.snapshots ?? []).every((row) => row.snapshot_ref !== PRE_LEG),
    `${(preLegList.j?.snapshots ?? []).length} rows`);
  const preLegRestore = await jd("POST", `/v1/hypervisor/snapshots/${PRE_LEG}/restore`, null, { as: "A" });
  const preLegDuty = await jd("POST", "/v1/hypervisor/retention/dispositions", {
    subject_kind: "environment_workspace_capture", subject_ref: PRE_LEG, policy_basis_ref: POLICY,
    owner_ref: P.A.owner, idempotency_key: "env-custody-preleg-1",
  }, { as: "A" });
  ok("and it can be neither restored NOR named as a retention subject — so its bytes cannot be destroyed through the estate's only deletion path, by anyone",
    preLegRestore.status === 403 && preLegDuty.status === 403
      && fs.existsSync(path.join(preLegDir, "workspace.tar")),
    `restore ${preLegRestore.status} declare ${preLegDuty.status} bytes still on disk ${fs.existsSync(path.join(preLegDir, "workspace.tar"))}`);

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
  const isolationAfterRestart = await jd("POST", `/v1/hypervisor/snapshots/${encodeURIComponent(foreignCapture)}/restore`, null, { as: "A" });
  ok("and the per-principal CAPTURE pin survives the restart — A still cannot reach B's capture",
    isolationAfterRestart.status === 403, `status ${isolationAfterRestart.status} code ${code(isolationAfterRestart.j)}`);

  // ------------------------------------------------------------ the derived closed world
  const sourceCensus = deriveEnvironmentOwnerCensus(ROOT);
  const key = routeKey;
  ok("THE ROUTER CLOSED WORLD resolves every registered handler across every module — an unresolved handler cannot disappear from the authority census",
    sourceCensus.registered_route_handlers > 0 && sourceCensus.unresolved.length === 0,
    sourceCensus.unresolved.map((route) => route.handler).join(", ") || `${sourceCensus.registered_route_handlers} registered handlers resolved`);
  ok("EVERY transitively reached environment/workspace sink is positively classified — a new route cannot land as an unnamed residual",
    sourceCensus.workspace_route_handlers > 0 && sourceCensus.unclassified.length === 0,
    sourceCensus.unclassified.map((route) => `${key(route)} -> ${route.handler}`).join(", ") || `${sourceCensus.workspace_route_handlers} owner-authorized route handlers`);
  const inventoryKeys = new Set(sourceCensus.routes.map(key));
  const staleCustody = CUSTODY_ROUTES.filter((entry) => !inventoryKeys.has(key(entry)));
  ok("the three live capture/restore probes are members of that derived call-graph census — the runtime test cannot claim coverage outside its source inventory",
    staleCustody.length === 0,
    staleCustody.map(key).join(", ") || `${CUSTODY_ROUTES.length} custody mutations found in the derived census`);

  const anonymousRefusals = [];
  // Re-snapshot HERE. This is a delta assertion and the fixtures between the previous snapshot and
  // this loop legitimately move the count; comparing against a stale baseline would fail for a
  // reason that has nothing to do with anonymous callers.
  tarsBefore = materialTars();
  for (const endpoint of CUSTODY_ROUTES) {
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
