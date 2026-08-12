// verify-hypervisor-work-cockpit — the Work PARTIAL PRE-W3 COCKPIT SLICE verifier
// (check:work-cockpit, next-legs IV Leg 3). Deliberately NOT a "-journey": the Work journey
// (admission→harness→run→events/receipts→stop/archive/recovery/replay) is W3.1's to earn;
// SURF-work and W3.1 REMAIN OPEN and nothing here claims Work completion.
//
// What this verifier proves, live against an isolated daemon + serve stack:
//   - the session family's owned verb set is pinned EXACTLY at /v1 (list/create · overview ·
//     get/teardown · events · execute · ports/revoke) — no stop, no archive, no lineage family;
//   - the launch chain is a TYPED ABSENCE per the delta ledger's HarnessSessionExecutionChain
//     row: recipe/binding/terminal-attach planners exist, NO typed HarnessSessionLaunch
//     producer exists, and the execution-binding stop/archive routes that DO exist bind the
//     chain W3.1 owns — this slice consumes none of them;
//   - the canonical mounts (/work, /work/sessions, /work/new-session) render the rehomed
//     cockpit grammar read-first with truthful ownership markers; the fresh legacy lanes serve
//     the same module; the protected seeds keep serving untouched (seed preservation);
//   - create → admitted readback: exactly ONE admitted session via POST /v1/hypervisor/sessions
//     on the identity-carrying action lane (202 + provision receipt), the ADMITTED harness
//     binding rendered as session truth recorded at create, and `subject_attachments: []`
//     pinned as the typed W3 C-1 absence even when project_ref was supplied (no masquerade);
//   - teardown (the destructive verb the daemon owns TODAY) transitions to torn_down with the
//     receipt ref recorded; stop/archive stay typed absences;
//   - bare /sessions answers the typed 410 at HTTP + body level (no redirect alias);
//   - deep link ≡ click-nav; reload + daemon-restart survival;
//   - the identity GATE (the #246 finding CLOSED — the #236/#240 W1.1/G-2 class): every session
//     write verb refuses typed 401 request_principal_required for anonymous callers under
//     loopback posture (rule E — before any record load, so no 404 existence oracle), the forged
//     internal-dispatch token forwards inert, the serve lane surfaces the refusal verbatim, and
//     the durable provision/teardown receipts bind acting_principal_ref (INV-37);
//   - the 3-posture browser matrix on /work.
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

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-work-cockpit-"));
let daemon = null;
let serve = null;
let daemonPort = 0;
let DAEMON = "";
let SERVE = "";
let SESSION = "";

const LANDING = "/work";
const SESSIONS_VIEW = "/work/sessions";
const NEW_SESSION = "/work/new-session";
const FRESH_LANDING = "/__ioi/work-cockpit";
const FRESH_SESSIONS = "/__ioi/work-sessions";
const FRESH_NEW_SESSION = "/__ioi/work-new-session";
const SEED_JOBS = "/__ioi/missions"; // protected seed (slug jobs)
const SEED_INCIDENTS = "/__ioi/missions/incidents"; // protected seed (slug incidents)

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

// A module-action form POST (PRG 303) — the redirect query carries acted/receipt/record/result
// or refused/reason; both are parsed, never followed blindly.
async function act(lane, tail, fields, { authenticated = true } = {}) {
  const r = await fetch(`${SERVE}${lane}${tail}`, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      ...(authenticated && SESSION ? { cookie: `ioi_session=${SESSION}` } : {}),
    },
    body: new URLSearchParams(fields).toString(),
    redirect: "manual",
  }).catch(() => null);
  const location = r?.headers?.get("location") || "";
  let q = new URLSearchParams();
  let pathOnly = "";
  try {
    const u = new URL(location, "http://x");
    q = u.searchParams;
    pathOnly = u.pathname;
  } catch { /* keep empty */ }
  return { status: r?.status ?? 0, location, path: pathOnly, q };
}

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
      body: JSON.stringify({ token, password: "work-cockpit-bootstrap-v1", email: "work-cockpit@ioi.local" }),
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

  // Launch chain (W3.1 LANDED): the typed HarnessSessionLaunch producer is now LIVE and COMPOSES
  // the canonical admission planners (recipe/binding/terminal-attach), which remain their owners.
  // The former typed-absence pin is FLIPPED — the producer family exists with produce/get/events/
  // stop/archive; its own chain journey is proven by check:launch-chain.
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
  // identity-first under EVERY posture, loopback included. The old FINDING(typed) rows are
  // REPLACED by these hard assertions.
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

  // -- serve boot -----------------------------------------------------------------------------
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
  await waitFor(`${SERVE}${LANDING}`, 30000);

  // -- canonical landing: rehomed cockpit grammar, read-first, scope-bounded ------------------
  const landing = await pageText(LANDING);
  ok("canonical /work 200s as the module's own mount (ownership headers name the served route + owner)",
    landing.status === 200
      && landing.headers.get("x-ioi-surface-route") === LANDING
      && landing.headers.get("x-ioi-surface-owner") === "Work",
    `route ${landing.headers.get("x-ioi-surface-route")} · owner ${landing.headers.get("x-ioi-surface-owner")}`);
  ok("the landing states its scope TYPED: the W3.1 launch chain is wired LIVE here, while SURF-work stays open on its other deps (W3.2/W3.3/operations)",
    landing.text.includes('data-ioi-scope="w3-1-launch-chain-live-surface-open"')
      && landing.text.includes("W3.1 landed")
      && landing.text.includes("SURF-work stays open"));
  ok("the jobs/incidents cockpit grammar is rehomed READ-FIRST: Run queue + Incidents & blockers panes render and their rows/sections LINK to the protected seeds exactly where the cockpit does",
    landing.text.includes("Run queue") && landing.text.includes("Incidents &amp; blockers")
      && landing.text.includes(`href="${SEED_JOBS}`) && landing.text.includes(`href="${SEED_INCIDENTS}`));
  ok("honest-empty everywhere on a fresh daemon: the queue and incidents bands state the no-fabrication rule instead of inventing rows",
    landing.text.includes("never fabricates rows") && landing.text.includes("never fabricates incidents"));
  ok("the eight typed canon views stay honest: Sessions is live, the other views are marked shell-only (SURF-work open), never faked",
    landing.text.includes(`href="${SESSIONS_VIEW}"`) && landing.text.includes('data-ioi-view-state="shell-only"'));

  const freshLanding = await pageText(FRESH_LANDING);
  ok("the fresh legacy lane /__ioi/work-cockpit serves the same module with truthful per-lane markers",
    freshLanding.status === 200
      && freshLanding.headers.get("x-ioi-surface-route") === FRESH_LANDING
      && freshLanding.text.includes("Run queue"),
    `route ${freshLanding.headers.get("x-ioi-surface-route")}`);

  // -- deep link ≡ click-nav ------------------------------------------------------------------
  const sessionsHref = (landing.text.match(/href="([^"]*)">Open Sessions/u) || [])[1] || "";
  const clickNav = await pageText(sessionsHref);
  const deepLink = await pageText(SESSIONS_VIEW);
  ok("deep link ≡ click-nav: following the landing's Sessions href and requesting the constructed deep link land on the same surface with the same ownership markers",
    sessionsHref === SESSIONS_VIEW
      && clickNav.status === 200 && deepLink.status === 200
      && clickNav.headers.get("x-ioi-surface-route") === deepLink.headers.get("x-ioi-surface-route")
      && clickNav.text.includes("Work / Sessions") && deepLink.text.includes("Work / Sessions"),
    sessionsHref);

  // -- sessions view: honest-empty + the W0.6 overview + typed W3 absences --------------------
  ok("/work/sessions renders the W0.6 counts-first overview with the daemon's own named gaps and the subject-attachment rollup as LIVE (materialized by the daemon at launch — W3.1)",
    deepLink.text.includes("Overview (W0.6)")
      && deepLink.text.includes("materialized by the daemon at launch")
      && deepLink.text.includes('data-ioi-w3-live="subject_attachments"'));
  ok("owner-filtered honest-empty: no sessions render for the fresh operator principal (session truth is owner-filtered before counts, and the gate admitted nothing anonymous to leak in)",
    deepLink.text.includes("No sessions for this principal yet"));

  const freshSessions = await pageText(FRESH_SESSIONS);
  ok("the fresh legacy lane /__ioi/work-sessions serves the same sessions view",
    freshSessions.status === 200 && freshSessions.headers.get("x-ioi-surface-route") === FRESH_SESSIONS && freshSessions.text.includes("Work / Sessions"));

  // -- new-session form: NO subject input, typed W3 note, admitted-binding statement ----------
  const newForm = await pageText(NEW_SESSION);
  ok("/work/new-session renders the one-click create with NO subject input of any kind — subject attachments are daemon-resolved at LAUNCH, never caller-named (anti-masquerade stated typed on the form)",
    newForm.status === 200
      && newForm.text.includes(`action="${FRESH_NEW_SESSION}/actions/create-session"`)
      && !/name="subject/u.test(newForm.text)
      && newForm.text.includes('data-ioi-w3-live="subject_attachments"')
      && newForm.text.includes("daemon-resolved at launch"));
  ok("project_ref is declared a session FIELD on the form — never a subject attachment (the anti-masquerade statement is typed)",
    newForm.text.includes("never masquerades as a subject attachment"));
  ok("the ADMITTED binding contract is stated: harness/model-route binding is admitted at create and read back as session truth, never UI state",
    newForm.text.includes("ADMITTED AT CREATE"));
  const freshNew = await pageText(FRESH_NEW_SESSION);
  ok("the fresh legacy lane /__ioi/work-new-session serves the same form",
    freshNew.status === 200 && freshNew.text.includes("New Session"));

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

  // -- serve-lane identity GATE: the ambient daemonFetch forwards the (absent) caller identity
  // and the daemon's typed refusal surfaces on the PRG redirect — never a fake success.
  const anonServe = await act(FRESH_NEW_SESSION, "/actions/create-session", { initial_input: "anon serve-lane posture probe" }, { authenticated: false });
  ok("GATE: an anonymous serve-lane create surfaces the daemon's typed refusal on the PRG redirect (refused=request_principal_required, no acted/receipt — no session admitted)",
    anonServe.status === 303 && anonServe.q.get("refused") === "request_principal_required"
      && !anonServe.q.get("acted") && !anonServe.q.get("receipt"),
    `refused=${anonServe.q.get("refused")}`);

  // -- the journey this slice DOES own: create → admitted readback ----------------------------
  const PROJECT_REF = "project:work-cockpit-slice";
  const created = await act(FRESH_NEW_SESSION, "/actions/create-session", {
    initial_input: "work-cockpit partial pre-W3 slice — admitted create",
    project_ref: PROJECT_REF,
  });
  const sessionRef = created.q.get("record") || "";
  ok("the operator's create admits exactly ONE session through the identity-carrying action lane: PRG 303 carries acted/receipt/record/result and the receipt is the provision receipt",
    created.status === 303
      && created.q.get("acted") === "create-session"
      && String(created.q.get("receipt") || "").startsWith("receipt://hypervisor/session-provision/")
      && sessionRef.startsWith("session:")
      && created.q.get("result") === "provisioned"
      && created.path === FRESH_SESSIONS,
    `record ${sessionRef} · receipt ${String(created.q.get("receipt") || "").slice(0, 52)}`);

  const record = await sessGet(sessionRef);
  ok("daemon readback: the record is provisioned, owned by the authenticated principal (daemon-resolved, never client-supplied), and carries the create-time binding facts",
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

  const detail = await pageText(`${SESSIONS_VIEW}?session=${encodeURIComponent(sessionRef)}`);
  const bindingAdmitted = record?.harness_binding && (record.harness_binding.profile_ref || record.harness_binding.harness);
  ok("admitted readback on /work/sessions: lifecycle facts render (state, environment, workspace, owner, receipts) and the harness binding cell renders the RECORD's truth — admitted at create, never UI state",
    detail.status === 200
      && detail.text.includes(sessionRef)
      && detail.text.includes("provisioned")
      && detail.text.includes("Session facts")
      && (bindingAdmitted
        ? detail.text.includes('data-ioi-binding="admitted-at-create"')
        : detail.text.includes('data-ioi-binding="execute-time-default"')),
    `binding ${bindingAdmitted ? "admitted" : "execute-time default"}`);
  ok("BEFORE launch the detail pane renders subject_attachments as the LIVE (daemon-resolved-at-launch) state — no attachment yet, never a masquerade at create",
    detail.text.includes('data-ioi-w3-live="subject_attachments"') && detail.text.includes("none yet"));
  ok("BEFORE launch the Launch control is a LIVE identity-bound form (data-ioi-live-verb=\"launch\"), while Tear down stays a named session-level disabled control",
    detail.text.includes('data-ioi-live-verb="launch"')
      && detail.text.includes('action="/__ioi/work-sessions/actions/launch"')
      && detail.text.includes(">Tear down</button>"));

  // -- the W3.1 FLIP, driven live: launch → the chain, terminalization, subject attachment ------
  const launched = await act(FRESH_SESSIONS, "/actions/launch", { session_ref: sessionRef });
  ok("the operator LAUNCHES the harness session through the identity-carrying action lane: PRG 303 carries acted=launch + a launch receipt + the launch_ref record",
    launched.status === 303
      && launched.q.get("acted") === "launch"
      && String(launched.q.get("receipt") || "").startsWith("receipt://hypervisor/harness-session-launch/")
      && String(launched.q.get("record") || "").startsWith("harness-session-launch:"),
    `acted=${launched.q.get("acted")} receipt=${String(launched.q.get("receipt") || "").slice(0, 48)}`);
  const launchedRecord = await sessGet(sessionRef);
  ok("the launch MATERIALIZED a real typed daemon-resolved subject attachment onto the Session record (subject_attachments flipped from [] to the daemon-resolved set — anti-masquerade, subject_kind resolved server-side)",
    Array.isArray(launchedRecord?.subject_attachments)
      && launchedRecord.subject_attachments.length >= 1
      && launchedRecord.subject_attachments.some((a) => a.resolved_by === "daemon-runtime" && a.subject_kind === "harness_session_launch"),
    JSON.stringify(launchedRecord?.subject_attachments));
  const launchedDetail = await pageText(`${SESSIONS_VIEW}?session=${encodeURIComponent(sessionRef)}`);
  ok("AFTER launch the detail pane renders the materialized subject attachment LIVE and the launch state, and the launch-chain verbs are LIVE: Stop + Archive forms and Terminal/Replay/Recovery readbacks (data-ioi-live-verb), never disabled placeholders",
    launchedDetail.text.includes('data-ioi-w3-live="subject_attachments"')
      && launchedDetail.text.includes('data-ioi-launch-state="launched"')
      && ["stop", "archive", "terminal", "replay", "recovery"].every((verb) => launchedDetail.text.includes(`data-ioi-live-verb="${verb}"`)),
    "launch-chain controls live");
  ok("the sessions table lists the admitted session with its lifecycle pill and binding cell",
    launchedDetail.text.includes("facts →") && launchedDetail.text.includes("Admitted binding"));

  // -- the verbs that exist TODAY, exercised at the daemon ------------------------------------
  const overview = await jd("/v1/hypervisor/sessions/overview");
  ok("the W0.6 overview counts the admitted session owner-filtered: total 1, provisioned 1, and ONE session now carries subject attachments (the launch materialized them — the rollup reads real record truth)",
    overview.status === 200
      && overview.body?.total === 1
      && overview.body?.by_lifecycle_state?.provisioned === 1
      && overview.body?.subject_attachments?.sessions_with_attachments === 1,
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

  // -- reload + daemon-restart survival -------------------------------------------------------
  let reload = { status: 0, text: "" };
  for (let attempt = 0; attempt < 3; attempt++) {
    reload = await pageText(`${SESSIONS_VIEW}?session=${encodeURIComponent(sessionRef)}`);
    if (reload.status === 200 && reload.text.includes(sessionRef)) break;
    await new Promise((r) => setTimeout(r, 1200));
  }
  ok("reload: the sessions view re-renders the admitted session from daemon truth",
    reload.status === 200 && reload.text.includes(sessionRef));

  const bindingBefore = JSON.stringify(record?.harness_binding ?? null);
  daemon.kill("SIGTERM");
  await new Promise((r) => setTimeout(r, 1200));
  await startDaemon();
  const survived = await sessGet(sessionRef);
  ok("daemon restart: the session record survives with the SAME facts — ref, provisioned state, admitted binding, and the launch-materialized subject_attachments (durable, not a process-memory fact)",
    !!survived && survived.session_ref === sessionRef
      && survived.lifecycle_state === "provisioned"
      && JSON.stringify(survived.harness_binding ?? null) === bindingBefore
      && Array.isArray(survived.subject_attachments) && survived.subject_attachments.length >= 1
      && survived.subject_attachments.some((a) => a.resolved_by === "daemon-runtime"),
    `binding ${bindingBefore.slice(0, 60)}`);
  let rerender = { status: 0, text: "" };
  for (let attempt = 0; attempt < 3; attempt++) {
    rerender = await pageText(`${SESSIONS_VIEW}?session=${encodeURIComponent(sessionRef)}`);
    if (rerender.status === 200 && rerender.text.includes(sessionRef)) break;
    await new Promise((r) => setTimeout(r, 1200));
  }
  ok("the canonical mount re-renders the surviving session after restart",
    rerender.status === 200 && rerender.text.includes(sessionRef) && rerender.text.includes("provisioned"));

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
  ok("the record survives teardown as truth (lifecycle_state torn_down), and the sessions view renders it honestly",
    afterTeardown?.lifecycle_state === "torn_down"
      && (await pageText(`${SESSIONS_VIEW}?session=${encodeURIComponent(sessionRef)}`)).text.includes("torn_down"));

  // -- seed preservation: the protected seeds + the T2 readout keep serving untouched ---------
  const seedJobs = await pageText(SEED_JOBS, { authenticated: false });
  const seedIncidents = await pageText(SEED_INCIDENTS, { authenticated: false });
  const seedSessionsRoot = await pageText("/__ioi/sessions", { authenticated: false });
  ok("seed preservation: the protected Jobs cockpit (/__ioi/missions) and Incidents inbox (/__ioi/missions/incidents) keep serving their rich UX — no refusal shell, no shrinkage",
    seedJobs.status === 200 && seedJobs.text.length > 1500 && !/route_retired|route retirement refusal/iu.test(seedJobs.text)
      && seedIncidents.status === 200 && seedIncidents.text.length > 1500 && !/route_retired/iu.test(seedIncidents.text),
    `${seedJobs.status}/${seedIncidents.status} · ${seedJobs.text.length}/${seedIncidents.text.length}B`);
  ok("the T2 sessions-root readout (/__ioi/sessions) — the grammar source this view rehomed — keeps serving untouched until the W4 cutover",
    seedSessionsRoot.status === 200 && seedSessionsRoot.text.includes("Sessions"), `status ${seedSessionsRoot.status}`);

  // -- 3-posture matrix -----------------------------------------------------------------------
  let pw = null;
  try { pw = await import("playwright"); } catch { pw = null; }
  if (!pw) {
    ok("posture matrix skipped — playwright unavailable", false, "install playwright to run the browser matrix");
  } else {
    const browser = await pw.chromium.launch();
    for (const [name, opts] of [
      ["light-desktop", { viewport: { width: 1440, height: 900 }, colorScheme: "light" }],
      ["dark-desktop", { viewport: { width: 1440, height: 900 }, colorScheme: "dark" }],
      ["narrow-reduced-motion", { viewport: { width: 390, height: 844 }, colorScheme: "light", reducedMotion: "reduce" }],
    ]) {
      const ctx = await browser.newContext(opts);
      const page = await ctx.newPage();
      const errors = [];
      page.on("console", (m) => { if (m.type() === "error") errors.push(m.text()); });
      const resp = await page.goto(`${SERVE}${LANDING}`, { waitUntil: "networkidle", timeout: 45000 }).catch(() => null);
      const body = resp ? await page.evaluate(() => document.body.innerText) : "";
      await page.keyboard.press("Tab");
      const focused = resp ? await page.evaluate(() => document.activeElement?.tagName ?? "") : "";
      ok(`posture ${name}: renders, keyboard-focusable, zero console errors`,
        resp && resp.status() === 200 && body.length > 0 && errors.length === 0 && focused !== "" && focused !== "BODY",
        errors[0]?.slice(0, 100) ?? `focus ${focused}`);
      await ctx.close();
    }
    await browser.close();
  }

  // -- daemon outage: typed degradation, zero fabricated rows ---------------------------------
  daemon.kill("SIGTERM");
  await new Promise((r) => setTimeout(r, 1200));
  const down = await pageText(LANDING);
  ok("daemon down: the cockpit renders typed degradation — degradation codes named, zero fabricated queue/incident/session rows",
    down.status === 200 && down.text.includes("data-ioi-degraded=") && !down.text.includes("facts →"),
    `status ${down.status}`);
}

run().then(() => {
  const fails = results.filter((r) => !r.pass);
  for (const r of results) console.log(`${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? ` — ${r.detail}` : ""}`);
  console.log(`\n${results.length - fails.length}/${results.length} passed`);
  emitVerifierCensus({ verifierId: "work-cockpit", sourceUrl: import.meta.url, results });
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
