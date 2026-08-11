// verify-hypervisor-home-cockpit — the Home PARTIAL PRE-W3 COCKPIT SLICE verifier
// (check:home-cockpit, next-legs IV Leg 4). Deliberately NOT a "-journey": the Home journey
// (the manifest SURF-home acceptance — resumable/blocked/failed/approval-requiring/completed
// work with full state survival) is SURF-home's to earn; SURF-home and W3.1 REMAIN OPEN and
// nothing here claims Home completion.
//
// What this verifier proves, live against an isolated daemon + serve stack:
//   - the home-cockpit projection pair is a TYPED W3 ABSENCE pinned mechanically at /v1
//     (GET /v1/hypervisor/home-cockpit and /v1/hypervisor/session-operations are route-missing)
//     and stated typed on the page — the metrics strip is never a fabricated rollup;
//   - canonical /home renders every pane owner-backed from REAL routes only, HONEST-EMPTY on a
//     fresh daemon BEFORE any seeding (zeros stated as absence, never invented rows);
//   - seeded fixtures (an approval request, a project, a session) surface as REAL counts and
//     rows, and every LIVE deep-link target answers 200 showing the linked record class
//     (/governance/approvals, /work/sessions, /projects via the browser, /applications);
//   - the Operations-targeted links are a typed disabled-named-gap with the exact reason —
//     and the gap is REAL, pinned mechanically (/operations serves only the substrate shell,
//     no Operations surface module binds it; the pin fails the day the mount lands);
//   - the applications grid is compiler-projection truth ONLY: the page's entry set equals the
//     projection's entry set, launchable tiles link the projection's own routes, and the
//     folded-owner refusal set holds (no retired owner name renders anywhere);
//   - the cross-surface New Session journey: /home advertises Work's affordance at
//     /work/new-session, the create admits exactly ONE session (202 + provision receipt) on the
//     identity-carrying action lane, subject-less per the typed W3 C-1 absence
//     (subject_attachments EXACTLY []), and Home renders the admitted readback;
//   - /ai keeps serving untouched (current live entry, never a substitute seed);
//   - reload + daemon-restart survival of counts; daemon outage renders the typed
//     unavailability page with ZERO fabricated counts (the canon fallback-fixture rule,
//     api.md:167-169); the 3-posture browser matrix on /home.
//
// Exit: 0 pass · 1 fail · 2 blocked (daemon binary missing).
//   IOI_HYPERVISOR_DAEMON_BINARY  default target/debug/hypervisor-daemon

import { spawn } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import net from "node:net";
import { fileURLToPath } from "node:url";

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

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-home-cockpit-"));
let daemon = null;
let serve = null;
let daemonPort = 0;
let DAEMON = "";
let SERVE = "";
let SESSION = "";

const HOME = "/home";
const FRESH_HOME = "/__ioi/home-cockpit";
const LINK_APPROVALS = "/governance/approvals";
const LINK_SESSIONS = "/work/sessions";
const LINK_NEW_SESSION = "/work/new-session";
const LINK_PROJECTS = "/projects";
const LINK_APPLICATIONS = "/applications";
const WORK_NEW_SESSION_ACTION_LANE = "/__ioi/work-new-session";
const RETIRED_OWNER_NAMES = ["Missions", "Marketplace", "Workbench", "Agent Studio"];

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

const jd = (p, init, cookie = true) => fetch(`${DAEMON}${p}`, {
  ...init,
  headers: {
    ...(init?.body ? { "content-type": "application/json" } : {}),
    ...(cookie && SESSION ? { cookie: `ioi_session=${SESSION}` } : {}),
  },
}).then(async (r) => ({ status: r.status, body: await r.json().catch(() => ({})) }))
  .catch(() => ({ status: 0, body: {} }));

const pageText = (p, { authenticated = true } = {}) => fetch(`${SERVE}${p}`, {
  headers: authenticated && SESSION ? { cookie: `ioi_session=${SESSION}` } : {},
}).then(async (r) => ({ status: r.status, text: await r.text(), headers: r.headers }))
  .catch(() => ({ status: 0, text: "", headers: new Headers() }));

// A module-action form POST (PRG 303) — the redirect query carries acted/receipt/record/result
// or refused/reason; both are parsed, never followed blindly.
async function act(lane, tail, fields) {
  const r = await fetch(`${SERVE}${lane}${tail}`, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      ...(SESSION ? { cookie: `ioi_session=${SESSION}` } : {}),
    },
    body: new URLSearchParams(fields).toString(),
    redirect: "manual",
  }).catch(() => null);
  const location = r?.headers?.get("location") || "";
  let q = new URLSearchParams();
  try {
    q = new URL(location, "http://x").searchParams;
  } catch { /* keep empty */ }
  return { status: r?.status ?? 0, location, q };
}

const entryNames = (html) => [...html.matchAll(/data-ioi-entry-name="([^"]*)"/gu)].map((m) => m[1]).sort();

async function run() {
  daemonPort = await freePort();
  DAEMON = `http://127.0.0.1:${daemonPort}`;
  const daemonLogFn = await startDaemon();
  const token = daemonLogFn().match(/ioi_bootstrap_[a-f0-9]{64}/gu)?.at(-1) ?? null;
  if (token) {
    const boot = await jd("/v1/hypervisor/auth/bootstrap", {
      method: "POST",
      body: JSON.stringify({ token, password: "home-cockpit-bootstrap-v1", email: "home-cockpit@ioi.local" }),
    });
    SESSION = boot.body?.session_token ?? "";
  }
  ok("operator bootstrap yields an authenticated session", SESSION.startsWith("ioi_sess_"), SESSION.slice(0, 12));

  // -- TYPED W3 ABSENCE (mechanical): the home-cockpit projection pair is route-missing -------
  const index = await jd("/v1");
  const idxStr = JSON.stringify(index.body);
  ok("typed W3 absence pinned mechanically: GET /v1/hypervisor/home-cockpit (home_cockpit_projection.v1, api.md:132-169) and GET /v1/hypervisor/session-operations (api.md:171-181) are route-missing at the daemon — the W3 build list owns them; this slice may only compose per-family reads, never simulate the rollup",
    !idxStr.includes("home-cockpit") && !idxStr.includes("home_cockpit") && !idxStr.includes("session-operations"),
    "zero home-cockpit/session-operations hits at /v1");

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
  await waitFor(`${SERVE}${HOME}`, 30000);

  // -- HONEST-EMPTY PASS on the fresh daemon, BEFORE any seeding ------------------------------
  const empty = await pageText(HOME);
  ok("canonical /home 200s as the module's own mount (ownership headers name the served route + owner)",
    empty.status === 200
      && empty.headers.get("x-ioi-surface-route") === HOME
      && empty.headers.get("x-ioi-surface-owner") === "Home",
    `route ${empty.headers.get("x-ioi-surface-route")} · owner ${empty.headers.get("x-ioi-surface-owner")}`);
  ok("the page states its scope TYPED: partial pre-W3 cockpit slice, NOT Home completion (SURF-home and W3.1 remain open; the manifest SURF-home acceptance is the full bar)",
    empty.text.includes('data-ioi-scope="partial-pre-w3-cockpit-slice"')
      && empty.text.includes("NOT Home completion")
      && empty.text.includes("SURF-home and W3.1 remain open"));
  ok("every pane is present on the fresh render: approvals waiting · parked/failed runs · recent sessions · recent projects · applications grid · the New Session entry to Work's affordance",
    empty.text.includes('id="home-approvals"')
      && empty.text.includes('id="home-parked-failed"')
      && empty.text.includes('id="home-recent-sessions"')
      && empty.text.includes('id="home-recent-projects"')
      && empty.text.includes('id="home-applications"')
      && new RegExp(`<a[^>]*href="${LINK_NEW_SESSION}"[^>]*data-ioi-new-session-entry`, "u").test(empty.text));
  ok("honest-empty everywhere BEFORE seeding: all five owner-backed panes state typed absence-of-rows (approvals, parked-runs, failed-runs, sessions, projects) and ZERO record rows render",
    ["approvals", "parked-runs", "failed-runs", "sessions", "projects"].every((k) => empty.text.includes(`data-ioi-honest-empty="${k}"`))
      && !empty.text.includes("data-ioi-approval-row")
      && !empty.text.includes("data-ioi-session-row")
      && !empty.text.includes("data-ioi-project-row")
      && !empty.text.includes("data-ioi-parked-row")
      && !empty.text.includes("data-ioi-failed-row"));
  ok("the metrics-strip absence renders TYPED on the page (the home-cockpit projection is W3's, never a fabricated rollup)",
    empty.text.includes('data-ioi-w3-absence="home_cockpit_projection"')
      && empty.text.includes("route-missing"));
  ok("Home declares itself read-only: New Session is Work's affordance advertised by navigation (Home mints nothing), and the module declares zero actions",
    empty.text.includes("never mints the object itself") && empty.text.includes("Home owns no truth"));

  const freshHome = await pageText(FRESH_HOME);
  ok("the fresh legacy lane /__ioi/home-cockpit serves the same module with truthful per-lane markers",
    freshHome.status === 200
      && freshHome.headers.get("x-ioi-surface-route") === FRESH_HOME
      && freshHome.text.includes('id="home-approvals"'),
    `route ${freshHome.headers.get("x-ioi-surface-route")}`);

  // -- the Operations gap: typed on the page, REAL at the estate ------------------------------
  ok("the Operations-targeted links are a typed disabled-named-gap with the exact reason (counts real, links disabled until the Operations mount lands — never a dead link, never a fabricated destination)",
    empty.text.includes('data-ioi-named-gap="operations-mount"')
      && empty.text.includes("disabled-named-gap — the canonical Operations mount is not live")
      && empty.text.includes("GET /v1/hypervisor/failover/runs · GET /v1/hypervisor/operations")
      && empty.text.includes("never a dead link and never a fabricated destination"));
  const opsServe = await pageText("/operations");
  ok("the gap is REAL, pinned mechanically: /operations serves only the W0.1 substrate shell (owner marker 'substrate', no Operations surface module) — the day an Operations mount lands this pin fails and the gap must be re-ruled",
    opsServe.status === 200 && opsServe.headers.get("x-ioi-surface-owner") === "substrate",
    `owner ${opsServe.headers.get("x-ioi-surface-owner")}`);

  // -- /ai: the current live entry keeps serving untouched ------------------------------------
  const ai = await pageText("/ai", { authenticated: false });
  ok("/ai still serves the explorer readout untouched — a CURRENT LIVE ENTRY (never a substitute seed; the greenfield lane claims no parity with it)",
    ai.status === 200 && ai.text.length > 50000, `${ai.status} · ${ai.text.length}B`);

  // -- retired owner names never render -------------------------------------------------------
  ok("no retired owner name renders on the fresh /home (Missions · Marketplace · Workbench · Agent Studio — the folded-owner refusal set holds)",
    RETIRED_OWNER_NAMES.every((name) => !empty.text.includes(name)));

  // -- SEED real fixtures via the daemon ------------------------------------------------------
  const apprSeed = await jd("/v1/hypervisor/governance/approval-requests", {
    method: "POST",
    body: JSON.stringify({
      subject_ref: "canon://hypervisor/home-cockpit-slice",
      request_kind: "home_cockpit_check",
      reason: "home cockpit slice fixture — pending approval seed",
    }),
  });
  const apprId = apprSeed.body?.approval_request?.id || "";
  ok("fixture: an approval request seeds through the daemon and is pending",
    (apprSeed.status === 200 || apprSeed.status === 201 || apprSeed.status === 202)
      && !!apprId
      && (apprSeed.body?.approval_request?.status ?? "pending") === "pending",
    `${apprSeed.status} · ${apprId}`);

  const PROJECT_NAME = "home-cockpit-fixture";
  const projSeed = await fetch(`${SERVE}/api/ioi.v1.ProjectService/CreateProject`, {
    method: "POST",
    headers: { "content-type": "application/json", ...(SESSION ? { cookie: `ioi_session=${SESSION}` } : {}) },
    body: JSON.stringify({ name: PROJECT_NAME, initializer: { specs: [{ git: { remoteUri: "https://example.invalid/home/fixture.git" } }] } }),
  }).then(async (r) => ({ status: r.status, body: await r.json().catch(() => ({})) })).catch(() => ({ status: 0, body: {} }));
  const projectId = projSeed.body?.project?.id || "";
  ok("fixture: a project seeds through the identity-forwarding serve lane and is durable daemon truth",
    projSeed.status === 200 && !!projectId
      && (await jd(`/v1/hypervisor/projects/${encodeURIComponent(projectId)}`)).status === 200,
    `${projSeed.status} · ${projectId}`);

  const sessSeed = await jd("/v1/hypervisor/sessions", {
    method: "POST",
    body: JSON.stringify({ initial_input: "home cockpit slice fixture session" }),
  });
  const seedSessionRef = sessSeed.body?.session_ref || "";
  ok("fixture: a session seeds via POST /v1/hypervisor/sessions under the operator identity (202 + provision receipt)",
    sessSeed.status === 202 && seedSessionRef.startsWith("session:")
      && String(sessSeed.body?.receipt_ref || "").startsWith("receipt://"),
    `${sessSeed.status} · ${seedSessionRef.slice(0, 24)}`);

  // -- the seeded counts and rows render owner-backed -----------------------------------------
  const seeded = await pageText(HOME);
  ok("approvals waiting reflects the seeded fixture: count 1, the request renders as a row (kind + subject), deep-linking /governance/approvals",
    seeded.text.includes("1 waiting")
      && seeded.text.includes("home_cockpit_check")
      && seeded.text.includes("canon://hypervisor/home-cockpit-slice")
      && seeded.text.includes("data-ioi-approval-row")
      && seeded.text.includes(`href="${LINK_APPROVALS}"`));
  ok("recent sessions reflects the seeded fixture: count 1, the session ref renders as a resume row deep-linking /work/sessions",
    seeded.text.includes("1 session")
      && seeded.text.includes(seedSessionRef)
      && seeded.text.includes("data-ioi-session-row")
      && seeded.text.includes(`href="${LINK_SESSIONS}?session=${encodeURIComponent(seedSessionRef)}"`));
  ok("recent projects reflects the seeded fixture: count 1, the project renders as a row deep-linking /projects",
    seeded.text.includes("1 project")
      && seeded.text.includes(PROJECT_NAME)
      && seeded.text.includes("data-ioi-project-row")
      && seeded.text.includes(`href="${LINK_PROJECTS}"`));
  ok("the parked/failed panes stay honest-empty (no failover/operations fixtures exist) — real zeros stated as absence, never invented rows",
    seeded.text.includes('data-ioi-honest-empty="parked-runs"')
      && seeded.text.includes('data-ioi-honest-empty="failed-runs"'));

  // -- applications grid = compiler-projection truth ONLY -------------------------------------
  const projection = await jd("/v1/hypervisor/product-surface-projections", {
    method: "POST",
    body: JSON.stringify({ context: { launcher: "home-cockpit-verifier" } }),
  });
  const projectionEntries = Array.isArray(projection.body?.application_entries) ? projection.body.application_entries : [];
  const expectedNames = projectionEntries.map((e) => String(e.display_name || e.identity_ref || "")).sort();
  const pageNames = entryNames(seeded.text);
  ok("the applications grid renders EXACTLY the projection's entry set — nothing the projection wouldn't admit, nothing the projection admits hidden",
    projection.status === 200 && expectedNames.length > 0 && JSON.stringify(pageNames) === JSON.stringify(expectedNames),
    `page ${pageNames.length} entries vs projection ${expectedNames.length}`);
  const launchables = projectionEntries.filter((e) => e.launchable === true && typeof e.resolved_launch_route === "string");
  ok("launchable tiles link the projection's own resolved_launch_route; non-launchable entries render disabled with their typed reasons — launch state is projection truth, never invented",
    launchables.length > 0
      && launchables.every((e) => seeded.text.includes(`href="${e.resolved_launch_route}"`))
      && projectionEntries.filter((e) => e.launchable !== true)
        .every((e) => new RegExp(`data-ioi-entry-name="${String(e.display_name || e.identity_ref || "").replace(/[.*+?^${}()|[\]\\]/gu, "\\$&")}" data-ioi-launchable="false"`, "u").test(seeded.text)),
    `${launchables.length} launchable`);
  ok("no retired owner name renders on the seeded /home either (refusal set holds over live projection truth)",
    RETIRED_OWNER_NAMES.every((name) => !pageNames.includes(name)));

  // -- follow the actual hrefs: every LIVE deep-link target shows the linked record class -----
  const apprPage = await pageText(LINK_APPROVALS);
  ok("deep link /governance/approvals: 200 under the Governance owner and the seeded approval request renders (the linked record class, followed from Home's own href)",
    apprPage.status === 200
      && apprPage.headers.get("x-ioi-surface-owner") === "Governance"
      && (apprPage.text.includes("home_cockpit_check") || apprPage.text.includes(apprId)),
    `owner ${apprPage.headers.get("x-ioi-surface-owner")}`);
  const sessHref = (seeded.text.match(new RegExp(`href="(${LINK_SESSIONS}\\?session=[^"]*)"`, "u")) || [])[1] || "";
  const sessPage = await pageText(sessHref);
  ok("deep link /work/sessions?session=…: 200 under the Work owner and the seeded session's facts render (followed from Home's own resume row href)",
    !!sessHref && sessPage.status === 200
      && sessPage.headers.get("x-ioi-surface-owner") === "Work"
      && sessPage.text.includes(seedSessionRef)
      && sessPage.text.includes("Session facts"),
    sessHref.slice(0, 60));
  const projPage = await pageText(LINK_PROJECTS);
  ok("deep link /projects: the vendored Projects subtree serves 200 (its record class is asserted in the browser below — the page is client-rendered)",
    projPage.status === 200 && projPage.text.length > 10000, `${projPage.status} · ${projPage.text.length}B`);
  const appsPage = await pageText(LINK_APPLICATIONS);
  ok("deep link /applications: 200 under the Applications owner with the full catalog (the grid's 'full launcher' href lands on the one compiled projection)",
    appsPage.status === 200
      && appsPage.headers.get("x-ioi-surface-owner") === "Applications"
      && appsPage.text.includes("Application catalog"));
  const firstLaunch = launchables[0];
  const launchTarget = firstLaunch ? await pageText(firstLaunch.resolved_launch_route) : { status: 0 };
  ok("following a launchable tile's href lands 200 — launch is navigation over an admitted projection row, never a mutation",
    !!firstLaunch && launchTarget.status === 200,
    firstLaunch ? `${firstLaunch.display_name} → ${firstLaunch.resolved_launch_route}` : "no launchable entries");

  // -- the cross-surface New Session journey (subject-less, per the typed W3 C-1 absence) -----
  const newSessionPage = await pageText(LINK_NEW_SESSION);
  ok("the New Session entry advertises Work's affordance: /work/new-session 200s under the Work owner with NO subject input (the typed W3 C-1 absence stated on the form)",
    newSessionPage.status === 200
      && newSessionPage.headers.get("x-ioi-surface-owner") === "Work"
      && !/name="subject/u.test(newSessionPage.text)
      && newSessionPage.text.includes('data-ioi-w3-absence="subject_attachments"'));
  const created = await act(WORK_NEW_SESSION_ACTION_LANE, "/actions/create-session", {
    initial_input: "home cockpit cross-surface journey — admitted create",
  });
  const journeyRef = created.q.get("record") || "";
  ok("the journey create admits exactly ONE session through the identity-carrying action lane (PRG 303, provision receipt, session record)",
    created.status === 303
      && created.q.get("acted") === "create-session"
      && String(created.q.get("receipt") || "").startsWith("receipt://hypervisor/session-provision/")
      && journeyRef.startsWith("session:")
      && created.q.get("result") === "provisioned",
    `record ${journeyRef.slice(0, 24)}`);
  const journeyRecord = (await jd(`/v1/hypervisor/sessions/${encodeURIComponent(journeyRef)}`)).body?.session || null;
  ok("admitted readback at the daemon: provisioned, owner daemon-resolved to the authenticated principal, and subject_attachments EXACTLY [] (subject-less — the typed W3 absence, never masqueraded)",
    !!journeyRecord && journeyRecord.lifecycle_state === "provisioned"
      && String(journeyRecord.owner_ref || "").startsWith("user://")
      && journeyRecord.owner_ref !== "user://local-operator"
      && Array.isArray(journeyRecord.subject_attachments) && journeyRecord.subject_attachments.length === 0,
    `owner ${journeyRecord?.owner_ref}`);
  const afterJourney = await pageText(HOME);
  ok("Home renders the admitted readback: the journey session joins Recent sessions (2 sessions, both refs) — cross-surface create lands back on owner-backed truth",
    afterJourney.text.includes("2 sessions")
      && afterJourney.text.includes(seedSessionRef)
      && afterJourney.text.includes(journeyRef));

  // -- reload survival ------------------------------------------------------------------------
  const reload = await pageText(HOME);
  ok("reload: /home re-renders every seeded count and row from daemon truth (nothing was page-local state)",
    reload.status === 200
      && reload.text.includes("1 waiting")
      && reload.text.includes("2 sessions")
      && reload.text.includes(PROJECT_NAME)
      && reload.text.includes(journeyRef));

  // -- daemon-restart survival ----------------------------------------------------------------
  daemon.kill("SIGTERM");
  await new Promise((r) => setTimeout(r, 1200));
  await startDaemon();
  let survived = { status: 0, text: "" };
  for (let attempt = 0; attempt < 3; attempt++) {
    survived = await pageText(HOME);
    if (survived.status === 200 && survived.text.includes(journeyRef)) break;
    await new Promise((r) => setTimeout(r, 1200));
  }
  ok("daemon restart: the approval, the project and both sessions survive as durable records and /home re-renders the same counts",
    survived.status === 200
      && survived.text.includes("1 waiting")
      && survived.text.includes("home_cockpit_check")
      && survived.text.includes(PROJECT_NAME)
      && survived.text.includes("2 sessions")
      && survived.text.includes(seedSessionRef)
      && survived.text.includes(journeyRef));

  // -- daemon outage: the typed unavailability page, zero fabricated counts -------------------
  daemon.kill("SIGTERM");
  await new Promise((r) => setTimeout(r, 1200));
  const down = await pageText(HOME);
  ok("daemon down: /home renders the TYPED unavailability page — the canon fallback-fixture rule held verbatim (nothing is shown rather than fixtures)",
    down.status === 200
      && down.text.includes('data-ioi-daemon-unavailable="true"')
      && down.text.includes("Daemon unreachable")
      && down.text.includes("data-ioi-scope"),
    `status ${down.status}`);
  ok("zero fabricated counts on the outage page: no approval kind, no project name, no session refs, no count pills, no honest-empty markers pretending the daemon answered",
    !down.text.includes("home_cockpit_check")
      && !down.text.includes(PROJECT_NAME)
      && !down.text.includes(seedSessionRef)
      && !down.text.includes(journeyRef)
      && !down.text.includes("waiting")
      && !down.text.includes("data-ioi-honest-empty"));
  await startDaemon();
  await waitFor(`${DAEMON}/healthz`, 30000);

  // -- 3-posture matrix on /home + the /projects record class in the browser ------------------
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
      const resp = await page.goto(`${SERVE}${HOME}`, { waitUntil: "networkidle", timeout: 45000 }).catch(() => null);
      const body = resp ? await page.evaluate(() => document.body.innerText) : "";
      await page.keyboard.press("Tab");
      const focused = resp ? await page.evaluate(() => document.activeElement?.tagName ?? "") : "";
      ok(`posture ${name}: /home renders, keyboard-focusable, zero console errors`,
        resp && resp.status() === 200 && body.length > 0 && errors.length === 0 && focused !== "" && focused !== "BODY",
        errors[0]?.slice(0, 100) ?? `focus ${focused}`);
      await ctx.close();
    }
    // /projects is the vendored client-rendered subtree: its record class is asserted here,
    // in the browser, following Home's own deep-link. (Pre-existing vendored console noise on
    // that page is not this slice's regression and is not asserted either way.)
    const ctx = await browser.newContext();
    await ctx.addCookies([{ name: "ioi_session", value: SESSION, url: SERVE }]);
    const page = await ctx.newPage();
    await page.goto(`${SERVE}${LINK_PROJECTS}`, { waitUntil: "networkidle", timeout: 45000 }).catch(() => null);
    let projectsBody = "";
    for (let attempt = 0; attempt < 5; attempt++) {
      await page.waitForTimeout(1500);
      projectsBody = await page.evaluate(() => document.body.innerText).catch(() => "");
      if (projectsBody.includes(PROJECT_NAME)) break;
    }
    ok("deep link /projects shows the linked record class in the browser: the seeded project renders on the vendored Projects subtree",
      projectsBody.includes(PROJECT_NAME), `body ${projectsBody.length}B`);
    await ctx.close();
    await browser.close();
  }
}

run().then(() => {
  const fails = results.filter((r) => !r.pass);
  for (const r of results) console.log(`${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? ` — ${r.detail}` : ""}`);
  console.log(`\n${results.length - fails.length}/${results.length} passed`);
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
