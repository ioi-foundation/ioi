// verify-hypervisor-session-authority — the SESSION PLANE's identity gate, owned-verb inventory
// and route-retirement contract (check:session-authority).
//
// PROVENANCE (E7, 2026-08-20). This file was `verify-hypervisor-work-cockpit.mjs`
// (check:work-cockpit, next-legs IV Leg 3), the verifier of the Work PARTIAL PRE-W3 COCKPIT SLICE.
// The E7 cockpit retirement removed that slice — its three registry rows, its module
// (surfaces/work/index.mjs) and its three mounts — so every assertion that drove a rendered
// /work · /work/sessions · /work/new-session page went with it. What did NOT go with it is the
// part of that verifier whose subject was never the cockpit: the daemon session family's identity
// gate, its exact owned-verb set, the durable INV-37 receipts on its two authority-crossing verbs,
// the served typed-410 for the retired /sessions root, and the protected seeds that keep serving.
// Those assertions are the estate's ONLY coverage of those facts, so they were re-aimed and kept
// here rather than deleted with the surface. The surface-driven journey they used to ride on is
// proven, end to end and better, by check:launch-chain (admission → launch → stop/archive →
// restart recovery over the same session plane).
//
// What this verifier proves, live against an isolated daemon + serve stack:
//   - the session family's owned verb set is pinned EXACTLY at /v1 (list/create · overview ·
//     get/teardown · events · execute · ports/revoke) — no session-level stop/archive, no
//     lineage/fork/children/transition/history family (typed W3 absences, never simulated);
//   - the typed HarnessSessionLaunch producer family is LIVE and the composed admission planners
//     remain their canonical owners (the W3.1 flip; the chain itself is check:launch-chain's);
//   - the identity GATE (the #246 finding CLOSED — the #236/#240 W1.1/G-2 class): every session
//     write verb refuses typed 401 request_principal_required for anonymous callers under loopback
//     posture (rule E — before any record load, so no 404 existence oracle), a FORGED
//     internal-dispatch token forwards inert, and an exposure-marked anonymous create fails closed;
//   - create → admitted readback at the daemon: 202 + provision receipt, owner daemon-resolved
//     (never client-supplied, never the loopback operator), `subject_attachments: []` pinned as the
//     typed W3 C-1 absence even when project_ref was supplied (no masquerade at create), and the
//     DURABLE provision receipt binding acting_principal_ref (INV-37);
//   - owner scoping on the list read and the W0.6 overview; the events SSE probed at the transport;
//   - daemon-restart survival of the record's facts;
//   - teardown — the one destructive session verb that exists today — transitions to torn_down
//     with a committed, principal-bound teardown receipt (INV-37);
//   - bare /sessions answers the typed 410 at HTTP + body level, HTML arm links the canonical
//     replacement, and the retired subtree carries the deep-link tail (no redirect alias);
//   - seed preservation: the protected Jobs cockpit, the Incidents inbox and the T2 sessions-root
//     readout keep serving untouched.
//
// Exit: 0 pass · 1 fail · 2 blocked (daemon binary missing).
//   IOI_HYPERVISOR_DAEMON_BINARY  default target/debug/hypervisor-daemon

import { spawn } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import net from "node:net";
import { fileURLToPath } from "node:url";
import { emitVerifierCensus } from "./lib/verifier-census.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const APP = path.resolve(HERE, "..");
const ROOT = path.resolve(APP, "..", "..");

const results = [];
const ok = (name, cond, detail) => results.push({ name, pass: !!cond, detail: detail || "" });

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
    try {
      const r = await fetch(url);
      if (r.status < 500) return;
    } catch { /* not up yet */ }
    await new Promise((r) => setTimeout(r, 400));
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

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-session-authority-"));
let daemon = null;
let serve = null;
let daemonPort = 0;
let DAEMON = "";
let SERVE = "";
let SESSION = "";

const SEED_JOBS = "/__ioi/missions"; // protected seed (slug jobs)
const SEED_INCIDENTS = "/__ioi/missions/incidents"; // protected seed (slug incidents)
const SEED_SESSIONS_ROOT = "/__ioi/sessions"; // the T2 sessions readout — the LIVE Sessions surface

async function startDaemon() {
  daemon = spawn(daemonBinary, [], {
    cwd: ROOT,
    env: {
      ...process.env,
      IOI_HYPERVISOR_DAEMON_ADDR: `127.0.0.1:${daemonPort}`,
      IOI_HYPERVISOR_DATA_DIR: dataDir,
      IOI_HYPERVISOR_MODEL_UPSTREAM: "http://127.0.0.1:1/v1",
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let log = "";
  daemon.stdout.on("data", (c) => { log = `${log}${c}`.slice(-64000); });
  daemon.stderr.on("data", (c) => { log = `${log}${c}`.slice(-64000); });
  await waitFor(`${DAEMON}/healthz`, 30000);
  return () => log;
}

// Daemon JSON — cookie=true carries the operator session; extraHeaders lets posture probes
// mark exposure without inventing a second helper.
const jd = (p, init, cookie = true, extraHeaders = {}) => fetch(`${DAEMON}${p}`, {
  ...init,
  headers: {
    ...(init?.body ? { "content-type": "application/json" } : {}),
    ...(cookie && SESSION ? { cookie: `ioi_session=${SESSION}` } : {}),
    ...extraHeaders,
  },
}).then(async (r) => ({ status: r.status, body: await r.json().catch(() => ({})) }))
  .catch(() => ({ status: 0, body: {} }));

// A served page, optionally with the operator session.
const pageText = (p, { authenticated = true } = {}) => fetch(`${SERVE}${p}`, {
  headers: authenticated && SESSION ? { cookie: `ioi_session=${SESSION}` } : {},
}).then(async (r) => ({ status: r.status, text: await r.text(), headers: r.headers }))
  .catch(() => ({ status: 0, text: "", headers: new Headers() }));

function sessionFamilyRoutes(index) {
  return (index.families ?? [])
    .flatMap((family) => family.paths ?? [])
    .filter((row) => row.path.startsWith("/v1/hypervisor/sessions"))
    .map((row) => ({ path: row.path, methods: [...row.methods].sort() }))
    .sort((left, right) => left.path.localeCompare(right.path));
}

const sessGet = async (ref) => (await jd(`/v1/hypervisor/sessions/${encodeURIComponent(ref)}`)).body?.session || null;

// Persisted session receipt by kind + ref (INV-37 assertions read the DURABLE receipt, not the
// response projection).
const readSessionReceipt = (kind, ref) => {
  try {
    for (const f of fs.readdirSync(path.join(dataDir, "receipts"))) {
      try {
        const j = JSON.parse(fs.readFileSync(path.join(dataDir, "receipts", f), "utf8"));
        if (j.kind === kind && j.session_ref === ref) return j;
      } catch { /* not JSON */ }
    }
  } catch { /* no receipts yet */ }
  return null;
};

async function run() {
  daemonPort = await freePort();
  DAEMON = `http://127.0.0.1:${daemonPort}`;
  const daemonLogFn = await startDaemon();
  const token = daemonLogFn().match(/ioi_bootstrap_[a-f0-9]{64}/gu)?.at(-1) ?? null;
  if (token) {
    const boot = await jd("/v1/hypervisor/auth/bootstrap", {
      method: "POST",
      body: JSON.stringify({ token, password: "session-authority-bootstrap-v1", email: "session-authority@ioi.local" }),
    });
    SESSION = boot.body?.session_token ?? "";
  }
  ok("operator bootstrap yields an authenticated session", SESSION.startsWith("ioi_sess_"), SESSION.slice(0, 12));

  // -- TYPED ABSENCES (mechanical): the session family's owned verb set, pinned EXACTLY ------
  const index = await jd("/v1");
  const idxStr = JSON.stringify(index.body);
  const familyRoutes = sessionFamilyRoutes(index.body);
  const expectedRoutes = [
    { path: "/v1/hypervisor/sessions", methods: ["GET", "POST"] },
    { path: "/v1/hypervisor/sessions/:id", methods: ["DELETE", "GET"] },
    { path: "/v1/hypervisor/sessions/:id/events", methods: ["GET"] },
    { path: "/v1/hypervisor/sessions/:id/execute", methods: ["POST"] },
    { path: "/v1/hypervisor/sessions/:id/ports/revoke", methods: ["POST"] },
    { path: "/v1/hypervisor/sessions/overview", methods: ["GET"] },
  ].sort((left, right) => left.path.localeCompare(right.path));
  ok("owned-verb inventory pinned: the session family is EXACTLY list/create · overview · get/teardown · events · execute · ports/revoke — NO session-level stop/archive, NO lineage/fork/children/transition/history family (typed W3 absences, never simulated)",
    JSON.stringify(familyRoutes) === JSON.stringify(expectedRoutes)
      && ["stop", "archive", "lineage", "fork", "children", "transition", "history"].every((verb) => !idxStr.includes(`/v1/hypervisor/sessions/:id/${verb}`)),
    JSON.stringify(familyRoutes.map((r) => r.path)));

  // Launch chain (W3.1 LANDED): the typed HarnessSessionLaunch producer is LIVE and COMPOSES the
  // canonical admission planners (recipe/binding/terminal-attach), which remain their owners. The
  // chain journey itself is proven by check:launch-chain; this pins only that the family exists.
  const launchProducerPaths = (index.body.families ?? [])
    .flatMap((family) => family.paths ?? [])
    .map((row) => row.path)
    .filter((p) => p.startsWith("/v1/hypervisor/harness-session-launches"))
    .sort();
  ok("launch-chain LIVE (W3.1): the typed HarnessSessionLaunch producer family exists (produce · get · events · stop · archive), and the composed admission planners remain their canonical owners",
    JSON.stringify(launchProducerPaths) === JSON.stringify([
      "/v1/hypervisor/harness-session-launches",
      "/v1/hypervisor/harness-session-launches/:id",
      "/v1/hypervisor/harness-session-launches/:id/archive",
      "/v1/hypervisor/harness-session-launches/:id/events",
      "/v1/hypervisor/harness-session-launches/:id/stop",
    ])
      && idxStr.includes("/v1/hypervisor/session-launch-recipe-admissions")
      && idxStr.includes("/v1/hypervisor/harness-session-binding-admissions")
      && idxStr.includes("/v1/hypervisor/harness-session-terminal-attachments"),
    JSON.stringify(launchProducerPaths));

  // -- identity GATE (the #246 finding CLOSED — the #236/#240 class): session writes are
  // identity-first under EVERY posture, loopback included.
  const anonCreate = await jd("/v1/hypervisor/sessions", { method: "POST", body: JSON.stringify({}) }, false);
  ok("GATE: an unauthenticated direct daemon session create refuses TYPED 401 request_principal_required under loopback dev posture — loopback is NOT an identity exemption for governed writes, and no session is admitted",
    anonCreate.status === 401 && anonCreate.body?.error?.code === "request_principal_required",
    `${anonCreate.status}/${anonCreate.body?.error?.code}`);
  // Rule E ordering: the 401 is owed BEFORE the record load, so a bogus ref answers 401 (never
  // the 404 existence oracle) on every write verb of the family.
  const anonExecute = await jd("/v1/hypervisor/sessions/session:rule-e-probe/execute", { method: "POST", body: JSON.stringify({ intent: "probe" }) }, false);
  const anonPorts = await jd("/v1/hypervisor/sessions/session:rule-e-probe/ports/revoke", { method: "POST", body: JSON.stringify({}) }, false);
  const anonTeardown = await jd("/v1/hypervisor/sessions/session:rule-e-probe", { method: "DELETE" }, false);
  ok("GATE rule E: anonymous execute + ports-revoke + teardown on an unknown ref ALL answer the typed 401 — identity precedes the record load, so no 404 existence oracle exists for anonymous callers",
    [anonExecute, anonPorts, anonTeardown].every((r) => r.status === 401 && r.body?.error?.code === "request_principal_required"),
    `${anonExecute.status}/${anonPorts.status}/${anonTeardown.status}`);
  // The per-boot internal dispatch token (the daemon's own orchestration lane) is unforgeable
  // from outside: a caller-supplied value forwards inert.
  const forged = await jd("/v1/hypervisor/sessions", { method: "POST", body: JSON.stringify({}) }, false,
    { "x-ioi-internal-dispatch": "idisp_forged0000000000000000000000000000000000000000000000000000000000" });
  ok("GATE: a FORGED x-ioi-internal-dispatch token forwards inert — the anonymous create still refuses 401 (the per-boot secret lives only in daemon process memory and is never emitted)",
    forged.status === 401 && forged.body?.error?.code === "request_principal_required",
    `${forged.status}/${forged.body?.error?.code}`);
  // Exposure-marked anonymous create: enforcement is context-aware (auto mode enforces when
  // exposed) — the same anonymous body must refuse TYPED once the request is marked forwarded.
  const exposedAnon = await jd("/v1/hypervisor/sessions", { method: "POST", body: JSON.stringify({}) }, false, { "x-ioi-forwarded": "product-shell" });
  ok("GATE: the SAME anonymous create marked exposed (x-ioi-forwarded) refuses TYPED 401 — context-aware enforcement fails closed (the auth middleware's typed authentication_required, or the family's own session_* refusal) and no session is admitted",
    exposedAnon.status === 401
      && (exposedAnon.body?.reason === "authentication_required"
        || ["session_authentication_required", "session_authenticated_principal_required"].includes(exposedAnon.body?.error?.code)),
    `${exposedAnon.status}/${exposedAnon.body?.reason || exposedAnon.body?.error?.code}`);

  // -- the admitted create, at the daemon (the surface that used to expose it is retired; the
  // AUTHORITY is not, and these are the facts it owes) ----------------------------------------
  const PROJECT_REF = "project:session-authority";
  const create = await jd("/v1/hypervisor/sessions", {
    method: "POST",
    body: JSON.stringify({ project_ref: PROJECT_REF, initial_input: "session-authority admitted create" }),
  });
  const sessionRef = create.body?.session_ref || "";
  ok("the operator's create admits exactly ONE session: 202 with the provision receipt ref and a canonical session ref",
    create.status === 202 && sessionRef.startsWith("session:")
      && String(create.body?.receipt_ref || "").startsWith("receipt://hypervisor/session-provision/"),
    `${create.status} ${sessionRef} · receipt ${String(create.body?.receipt_ref || "").slice(0, 52)}`);

  const record = await sessGet(sessionRef);
  ok("daemon readback: the record is provisioned, owned by the authenticated principal (daemon-resolved, never client-supplied, never the loopback operator), and carries the create-time binding facts",
    !!record && record.lifecycle_state === "provisioned"
      && String(record.owner_ref || "").startsWith("user://") && record.owner_ref !== "user://local-operator"
      && record.project_ref === PROJECT_REF,
    `owner ${record?.owner_ref} · project ${record?.project_ref}`);
  ok("ANTI-MASQUERADE PIN: subject_attachments is EXACTLY [] on the record even though project_ref was supplied — create hardcodes the empty set (the typed W3 C-1 absence) and project_ref stayed a session field",
    Array.isArray(record?.subject_attachments) && record.subject_attachments.length === 0,
    JSON.stringify(record?.subject_attachments));
  const provisionReceipt = readSessionReceipt("hypervisor.session.provision", sessionRef);
  ok("INV-37: the durable provision receipt binds acting_principal_ref — the identity-resolved creating principal (equal to the record owner, never the loopback operator, never client-supplied)",
    !!provisionReceipt && provisionReceipt.acting_principal_ref === record?.owner_ref
      && provisionReceipt.acting_principal_ref !== "user://local-operator",
    `acting ${provisionReceipt?.acting_principal_ref}`);

  // -- the verbs that exist TODAY, exercised at the daemon ------------------------------------
  const overview = await jd("/v1/hypervisor/sessions/overview");
  ok("the W0.6 overview counts the admitted session owner-filtered: total 1, provisioned 1, and ZERO sessions carry subject attachments before any launch (the rollup reads real record truth)",
    overview.status === 200
      && overview.body?.total === 1
      && overview.body?.by_lifecycle_state?.provisioned === 1
      && overview.body?.subject_attachments?.sessions_with_attachments === 0,
    JSON.stringify(overview.body?.subject_attachments));
  const anonList = await jd("/v1/hypervisor/sessions", {}, false);
  ok("owner scoping holds on the list read: the anonymous (loopback-operator) list never contains the operator's session",
    anonList.status === 200 && !(anonList.body?.sessions || []).some((s) => s.session_ref === sessionRef),
    `${(anonList.body?.sessions || []).length} rows`);
  const events = await (async () => {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 2000);
    try {
      const r = await fetch(`${DAEMON}/v1/hypervisor/sessions/${encodeURIComponent(sessionRef)}/events`, {
        headers: SESSION ? { cookie: `ioi_session=${SESSION}` } : {},
        signal: controller.signal,
      });
      const type = r.headers.get("content-type") || "";
      controller.abort();
      return { status: r.status, type };
    } catch {
      return { status: 0, type: "" };
    } finally {
      clearTimeout(timer);
    }
  })();
  ok("the events verb exists TODAY as the canonical SSE (real signals only) — probed at the transport, never simulated",
    events.status === 200 && events.type.includes("text/event-stream"), `${events.status} ${events.type}`);

  // -- daemon-restart survival ----------------------------------------------------------------
  const bindingBefore = JSON.stringify(record?.harness_binding ?? null);
  daemon.kill("SIGTERM");
  await new Promise((r) => setTimeout(r, 1200));
  await startDaemon();
  const survived = await sessGet(sessionRef);
  ok("daemon restart: the session record survives with the SAME facts — ref, provisioned state, owner and the admitted binding (durable, not a process-memory fact)",
    !!survived && survived.session_ref === sessionRef
      && survived.lifecycle_state === "provisioned"
      && survived.owner_ref === record?.owner_ref
      && JSON.stringify(survived.harness_binding ?? null) === bindingBefore,
    `binding ${bindingBefore.slice(0, 60)}`);

  // -- teardown: the destructive verb the daemon owns TODAY (stop/archive stay typed absences)
  const teardown = await jd(`/v1/hypervisor/sessions/${encodeURIComponent(sessionRef)}`, { method: "DELETE" });
  const teardownReceipts = (teardown.body?.latest_receipt_refs || []).filter((r) => String(r).includes("session-teardown"));
  ok("teardown journeys clean: DELETE answers torn_down with the teardown receipt recorded — the one destructive session verb that exists today",
    teardown.status === 200 && teardown.body?.decision === "torn_down" && teardownReceipts.length === 1,
    `${teardown.status} · ${teardownReceipts[0] || "no receipt"}`);
  const teardownReceipt = readSessionReceipt("hypervisor.session.teardown", sessionRef);
  ok("INV-37: the durable teardown receipt is committed AND binds acting_principal_ref — the authenticated principal that performed the destructive verb",
    teardownReceipt?.status === "committed" && teardownReceipt?.acting_principal_ref === record?.owner_ref,
    `status ${teardownReceipt?.status} · acting ${teardownReceipt?.acting_principal_ref}`);
  const afterTeardown = await sessGet(sessionRef);
  ok("the record survives teardown as TRUTH (lifecycle_state torn_down) — a destructive verb terminalizes the record, it does not erase it",
    afterTeardown?.lifecycle_state === "torn_down", `state ${afterTeardown?.lifecycle_state}`);

  // -- serve boot: the route-retirement contract + seed preservation ---------------------------
  const servePort = await freePort();
  const productUiPort = await freePort();
  SERVE = `http://127.0.0.1:${servePort}`;
  serve = spawn(process.execPath, [path.join(HERE, "serve-product-ui.mjs")], {
    cwd: APP,
    env: {
      ...process.env,
      PORT: String(servePort),
      PRODUCT_UI_PORT: String(productUiPort),
      IOI_PRODUCT_UI_PUBLIC: path.join(APP, "product-ui", "owned", "public"),
      IOI_HYPERVISOR_DAEMON_URL: DAEMON,
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  await waitFor(`${SERVE}${SEED_SESSIONS_ROOT}`, 30000);

  // -- bare /sessions: the typed 410, asserted at HTTP + body level ---------------------------
  const gone = await fetch(`${SERVE}/sessions`, { headers: { accept: "application/json" } })
    .then(async (r) => ({ status: r.status, body: await r.json().catch(() => ({})) }))
    .catch(() => ({ status: 0, body: {} }));
  ok("bare /sessions answers HTTP 410 with the full typed refusal record — schema, code, requested route, canonical replacement /work/sessions, and the three no-action facts",
    gone.status === 410
      && gone.body.schema_version === "ioi.hypervisor.route_retirement_refusal.v1"
      && gone.body.code === "hypervisor.route_retired"
      && gone.body.requested_route === "/sessions"
      && gone.body.canonical_replacement_route === "/work/sessions"
      && gone.body.read_performed === false
      && gone.body.mutation_performed === false
      && gone.body.final_invocation_performed === false,
    `${gone.status} → ${gone.body.canonical_replacement_route}`);
  const goneHtml = await fetch(`${SERVE}/sessions`, { headers: { accept: "text/html" } })
    .then(async (r) => ({ status: r.status, text: await r.text() })).catch(() => ({ status: 0, text: "" }));
  ok("the HTML arm of the 410 renders the refusal with a LINK to /work/sessions (no redirect alias — ADR 0022 Decision 2)",
    goneHtml.status === 410 && goneHtml.text.includes("/work/sessions"), `status ${goneHtml.status}`);
  const goneDeep = await fetch(`${SERVE}/sessions/some/deep/link`, { headers: { accept: "application/json" } })
    .then(async (r) => ({ status: r.status, body: await r.json().catch(() => ({})) }))
    .catch(() => ({ status: 0, body: {} }));
  ok("the retired subtree answers 410 too, carrying the deep-link tail onto the canonical replacement",
    goneDeep.status === 410 && String(goneDeep.body.canonical_replacement_route || "").startsWith("/work/sessions"),
    `${goneDeep.status} → ${goneDeep.body.canonical_replacement_route}`);

  // -- E7 retirement, asserted from the OTHER side: the retired cockpit lanes are GONE ---------
  // The eight legacy cockpit routes left the registry with their modules in the E7 code removal.
  // A retired route must not render a surface: nothing may answer with a registry ownership
  // marker, and no cockpit body may come back. (The SPA catch-all answering its own shell is
  // fine — that is "this route is not a surface", which is exactly the claim.)
  const RETIRED_LANES = [
    "/__ioi/applications-launcher", "/__ioi/systems-workspace", "/__ioi/automations-cockpit",
    "/__ioi/work-cockpit", "/__ioi/work-sessions", "/__ioi/work-new-session",
    "/__ioi/home-cockpit", "/__ioi/operations-cockpit",
  ];
  const retiredProbes = [];
  for (const lane of RETIRED_LANES) {
    const r = await pageText(lane);
    retiredProbes.push({ lane, status: r.status, owner: r.headers.get("x-ioi-surface-owner") || "", route: r.headers.get("x-ioi-surface-route") || "" });
  }
  ok("E7: every retired cockpit lane serves NO surface — none carries a registry ownership marker (x-ioi-surface-route/owner), so none is a registered surface any more",
    retiredProbes.every((p) => !p.owner && !p.route),
    retiredProbes.filter((p) => p.owner || p.route).map((p) => `${p.lane}→${p.owner}`).join(" ") || `${retiredProbes.length} lanes clean`);

  // -- seed preservation: the protected seeds + the T2 readout keep serving untouched ---------
  const seedJobs = await pageText(SEED_JOBS, { authenticated: false });
  const seedIncidents = await pageText(SEED_INCIDENTS, { authenticated: false });
  const seedSessionsRoot = await pageText(SEED_SESSIONS_ROOT, { authenticated: false });
  ok("seed preservation: the protected Jobs cockpit (/__ioi/missions) and Incidents inbox (/__ioi/missions/incidents) keep serving their rich UX — no refusal shell, no shrinkage",
    seedJobs.status === 200 && seedJobs.text.length > 1500 && !/route_retired|route retirement refusal/iu.test(seedJobs.text)
      && seedIncidents.status === 200 && seedIncidents.text.length > 1500 && !/route_retired/iu.test(seedIncidents.text),
    `${seedJobs.status}/${seedIncidents.status} · ${seedJobs.text.length}/${seedIncidents.text.length}B`);
  ok("the T2 sessions-root readout (/__ioi/sessions) — the LIVE Sessions surface, and the grammar source the retired Work view had rehomed — keeps serving untouched",
    seedSessionsRoot.status === 200 && seedSessionsRoot.text.includes("Sessions"), `status ${seedSessionsRoot.status}`);
}

run().then(() => {
  const fails = results.filter((r) => !r.pass);
  for (const r of results) console.log(`${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? ` — ${r.detail}` : ""}`);
  console.log(`\n${results.length - fails.length}/${results.length} passed`);
  emitVerifierCensus({ verifierId: "session-authority", sourceUrl: import.meta.url, results });
  cleanup();
  process.exit(fails.length ? 1 : 0);
}).catch((e) => {
  console.error("verifier crashed:", e);
  cleanup();
  process.exit(1);
});

function cleanup() {
  try { serve?.kill("SIGTERM"); } catch { /* gone */ }
  try { daemon?.kill("SIGTERM"); } catch { /* gone */ }
  try { fs.rmSync(dataDir, { recursive: true, force: true }); } catch { /* keep */ }
}
