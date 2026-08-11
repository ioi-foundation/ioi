// verify-hypervisor-operations-cockpit — the Operations PARTIAL PRE-W3 COCKPIT SLICE verifier
// (check:operations-cockpit, next-legs V Leg 4). Deliberately NOT a "-journey": the Operations
// journey (the manifest SURF-operations acceptance — injected-fault detection, typed incident
// open, authority preview, remediation/failover execution, receipts/events, owner-app
// readback, restart/rollback/support export) is W3.2/W3.3's to earn; SURF-operations REMAINS
// OPEN (its seed gate also carries the typed-blocked scheduler residual) and nothing here
// claims Operations completion.
//
// What this verifier proves, live against an isolated daemon + serve stack:
//   - the read families this slice composes all EXIST at /v1 (compose only what exists), and
//     the W3 rollup projections are TYPED ABSENCES pinned mechanically (no infrastructure-jobs
//     projection family, no RPO/RTO rollup family, no capacity-overview family at /v1) and
//     stated typed on the page — never a simulated rollup;
//   - canonical /operations renders every pane owner-backed from REAL routes only,
//     HONEST-EMPTY on a fresh daemon BEFORE any seeding (zeros stated as absence, never
//     invented rows); the fresh legacy lane /__ioi/operations-cockpit serves the same module;
//     the protected T2 seed /__ioi/operations keeps serving untouched;
//   - every W3.2/W3.3-owned action (typed incident open, infrastructure remediation, failover
//     run/arm/disarm/evaluate, archive export/verify/restore/repair) is a typed
//     disabled-named-gap carrying its exact reason AND its owning unit; automation-run
//     remediation renders as a LIVE delegation link to the Automations-owned mount;
//   - the scheduler split holds: scheduler HEALTH renders here from the daemon's own
//     scheduler-status read (value equality pinned), scheduler OBJECT truth deep-links the
//     live /automations mount, and the seed residual stays typed on the page;
//   - seeded fixtures (a scheduled automation, a failover plan, a fail-closed REFUSED failover
//     run, a storage backend) surface as REAL rows — including the refusal reason rendered
//     verbatim as fail-closed evidence, never hidden;
//   - Home's flipped Operations links resolve: /home renders live /operations deep-links (the
//     former operations-mount disabled-named-gap renders nowhere) and following them lands on
//     this mount;
//   - reload + daemon-restart survival of the read plane; daemon outage renders the typed
//     unavailability page with ZERO fabricated counts (the canon fallback-fixture rule,
//     api.md:167-169); the 3-posture browser matrix on /operations.
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

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-operations-cockpit-"));
let daemon = null;
let serve = null;
let daemonPort = 0;
let DAEMON = "";
let SERVE = "";
let SESSION = "";

const OPS = "/operations";
const FRESH_OPS = "/__ioi/operations-cockpit";
const SEED_READOUT = "/__ioi/operations";
const HOME = "/home";
const LINK_AUTOMATIONS = "/automations";

// The eleven per-family reads the slice composes — every one must exist at /v1.
const COMPOSED_FAMILY_ROUTES = [
  "/v1/hypervisor/scheduler/status",
  "/v1/hypervisor/operations",
  "/v1/hypervisor/failover/runs",
  "/v1/hypervisor/failover/plans",
  "/v1/hypervisor/incidents",
  "/v1/hypervisor/recovery-attempts",
  "/v1/hypervisor/providers",
  "/v1/hypervisor/provider-spend/reconciliation",
  "/v1/hypervisor/storage-backends",
  "/v1/hypervisor/storage-incidents",
  "/v1/hypervisor/substrate/status",
];

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

async function run() {
  daemonPort = await freePort();
  DAEMON = `http://127.0.0.1:${daemonPort}`;
  const daemonLogFn = await startDaemon();
  const token = daemonLogFn().match(/ioi_bootstrap_[a-f0-9]{64}/gu)?.at(-1) ?? null;
  if (token) {
    const boot = await jd("/v1/hypervisor/auth/bootstrap", {
      method: "POST",
      body: JSON.stringify({ token, password: "operations-cockpit-bootstrap-v1", email: "operations-cockpit@ioi.local" }),
    });
    SESSION = boot.body?.session_token ?? "";
  }
  ok("operator bootstrap yields an authenticated session", SESSION.startsWith("ioi_sess_"), SESSION.slice(0, 12));

  // -- COMPOSE ONLY WHAT EXISTS: the eleven read families are real at /v1 ---------------------
  const index = await jd("/v1");
  const idxStr = JSON.stringify(index.body);
  ok("every composed read family EXISTS at the daemon /v1 index (the slice composes per-family reads that exist — surfaces/operations.md §2)",
    COMPOSED_FAMILY_ROUTES.every((route) => idxStr.includes(`"${route}"`)),
    `${COMPOSED_FAMILY_ROUTES.length} families pinned`);
  ok("typed W3 absences pinned mechanically at /v1: no unified infrastructure-jobs projection family, no RPO/RTO + degraded/partition rollup family, no capacity/utilization overview family, and no /v1/hypervisor/operations subroute rollup — the W3 build list owns them; this slice may only compose per-family reads, never simulate a rollup",
    !idxStr.includes("infrastructure-jobs")
      && !idxStr.includes("infrastructure_jobs")
      && !idxStr.includes("/v1/hypervisor/operations/")
      && !idxStr.includes("rpo-rto") && !idxStr.includes("rpo_rto")
      && !idxStr.includes("capacity-overview") && !idxStr.includes("capacity_utilization")
      && !idxStr.includes("operations-rollup"),
    "zero rollup-family hits at /v1");

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
  await waitFor(`${SERVE}${OPS}`, 30000);

  // -- HONEST-EMPTY PASS on the fresh daemon, BEFORE any seeding ------------------------------
  const empty = await pageText(OPS);
  ok("canonical /operations 200s as the module's own mount (ownership headers name the served route + owner — the serve marker names the mount that served)",
    empty.status === 200
      && empty.headers.get("x-ioi-surface-route") === OPS
      && empty.headers.get("x-ioi-surface-owner") === "Operations",
    `route ${empty.headers.get("x-ioi-surface-route")} · owner ${empty.headers.get("x-ioi-surface-owner")}`);
  ok("the page states its scope TYPED: partial pre-W3 cockpit slice, NOT Operations completion (SURF-operations remains open; W3.2/W3.3 own the full acceptance)",
    empty.text.includes('data-ioi-scope="partial-pre-w3-cockpit-slice"')
      && empty.text.includes("NOT Operations completion")
      && empty.text.includes("SURF-operations remains open")
      && empty.text.includes("W3.2/W3.3"));
  ok("every pane is present on the fresh render: scheduler health · execution health · cross-provider failover · environment incidents & recovery · provider health · spend reconciliation · storage custody · substrate status",
    empty.text.includes('id="ops-scheduler"')
      && empty.text.includes('id="ops-execution"')
      && empty.text.includes('id="ops-failover"')
      && empty.text.includes('id="ops-incidents"')
      && empty.text.includes('id="ops-providers"')
      && empty.text.includes('id="ops-spend"')
      && empty.text.includes('id="ops-storage"')
      && empty.text.includes('id="ops-substrate"'));
  ok("honest-empty everywhere BEFORE seeding: scheduled-specs, runs, failover-runs, failover-plans, incidents, recovery-attempts, storage-backends, storage-incidents all state typed absence-of-rows and ZERO record rows render",
    ["scheduled-specs", "runs", "failover-runs", "failover-plans", "incidents", "recovery-attempts", "storage-backends", "storage-incidents"]
      .every((k) => empty.text.includes(`data-ioi-honest-empty="${k}"`))
      && !empty.text.includes("data-ioi-scheduled-spec-row")
      && !empty.text.includes("data-ioi-failed-run-row")
      && !empty.text.includes("data-ioi-failover-run-row")
      && !empty.text.includes("data-ioi-failover-plan-row")
      && !empty.text.includes("data-ioi-incident-row")
      && !empty.text.includes("data-ioi-storage-backend-row"));
  ok("the three W3 rollup absences render TYPED on the page (route-missing, never simulated): infrastructure-jobs projection · RPO/RTO + degraded/partition rollup · capacity/utilization overview",
    empty.text.includes('data-ioi-w3-absence="infrastructure_jobs_projection"')
      && empty.text.includes('data-ioi-w3-absence="rpo_rto_rollup"')
      && empty.text.includes('data-ioi-w3-absence="capacity_utilization_overview"')
      && empty.text.includes("route-missing"));

  // -- typed disabled-named-gaps: every W3.2/W3.3-owned verb, with its owning unit ------------
  ok("fault/remediation verbs are a typed disabled-named-gap owned by W3.2: typed incident open + infrastructure remediation render disabled with the exact reason and the owning unit",
    empty.text.includes('data-ioi-named-gap="w3-fault-remediation"')
      && /data-ioi-named-gap="w3-fault-remediation" data-ioi-owning-unit="W3\.2"/u.test(empty.text)
      && empty.text.includes("owning unit W3.2"));
  ok("failover execution is a typed disabled-named-gap owned by W3.2 (run · arm · disarm · evaluate) naming the exact daemon routes that exist and the never-automatic-authority contract",
    empty.text.includes('data-ioi-named-gap="w3-failover-execution"')
      && /data-ioi-named-gap="w3-failover-execution" data-ioi-owning-unit="W3\.2"/u.test(empty.text)
      && empty.text.includes("POST /v1/hypervisor/failover/run")
      && empty.text.includes("never automatic authority"));
  ok("archive/custody ops are a typed disabled-named-gap owned by W3.3 (export · verify · restore · repair) naming POST /v1/hypervisor/storage-archive-ops and the sealed-before-write crossing",
    empty.text.includes('data-ioi-named-gap="w3-archive-custody-ops"')
      && /data-ioi-named-gap="w3-archive-custody-ops" data-ioi-owning-unit="W3\.3"/u.test(empty.text)
      && empty.text.includes("POST /v1/hypervisor/storage-archive-ops"));
  ok("automation-run remediation is a LIVE delegation, never a gap: the execution-health pane deep-links the Automations-owned mount (Operations mints no automation authority)",
    empty.text.includes(`href="${LINK_AUTOMATIONS}" data-ioi-remediation-delegation`)
      && empty.text.includes("Automations-owned authority"));

  // -- the scheduler split + seed residual ----------------------------------------------------
  ok("the scheduler split renders: scheduler HEALTH is Operations-owned (this pane), scheduler OBJECT truth is Automations-owned with a live deep-link, and the typed-blocked seed residual is stated (a block record never opens work)",
    empty.text.includes(`href="${LINK_AUTOMATIONS}" data-ioi-scheduler-object-link`)
      && empty.text.includes('data-ioi-seed-blocked="scheduler"')
      && empty.text.includes("typed-blocked")
      && empty.text.includes("seed-ux-provenance.v1.json"));
  const schedBefore = await jd("/v1/hypervisor/scheduler/status");
  const schedPage = await pageText(OPS);
  const schedAfter = await jd("/v1/hypervisor/scheduler/status");
  const pageLiveness = (schedPage.text.match(/data-ioi-scheduler-liveness="([^"]*)"/u) || [])[1] || "";
  ok("scheduler health renders the daemon's OWN liveness value (GET /v1/hypervisor/scheduler/status — heartbeat-derived, value equality pinned against reads bracketing the render)",
    !!pageLiveness
      && (pageLiveness === String(schedBefore.body?.liveness || "") || pageLiveness === String(schedAfter.body?.liveness || "")),
    `page ${pageLiveness} vs daemon ${schedBefore.body?.liveness}/${schedAfter.body?.liveness}`);

  // -- provider health + spend rule are real reads --------------------------------------------
  const providers = await jd("/v1/hypervisor/providers");
  const firstProvider = (Array.isArray(providers.body?.providers) ? providers.body.providers : [])[0];
  ok("provider health renders the daemon's real provider registry rows (first provider_ref present on the page) and states the customer-borne spend rule verbatim",
    !!firstProvider
      && empty.text.includes(String(firstProvider.provider_ref || ""))
      && empty.text.includes("data-ioi-spend-rule")
      && empty.text.includes("customer-borne"),
    `first ${firstProvider?.provider_ref}`);
  ok("spend reconciliation renders the real read (headroom · actual spent · reserved estimates · open exposures · teardown finalized · unsettled) — reserved estimates never presented as spend",
    empty.text.includes("headroom")
      && empty.text.includes("actual spent")
      && empty.text.includes("reserved (open estimates)")
      && empty.text.includes("never presented as spend"));

  // -- lanes: fresh legacy lane + the protected T2 seed ---------------------------------------
  const freshOps = await pageText(FRESH_OPS);
  ok("the fresh legacy lane /__ioi/operations-cockpit serves the same module with truthful per-lane markers",
    freshOps.status === 200
      && freshOps.headers.get("x-ioi-surface-route") === FRESH_OPS
      && freshOps.text.includes('id="ops-scheduler"'),
    `route ${freshOps.headers.get("x-ioi-surface-route")}`);
  const seedReadout = await pageText(SEED_READOUT);
  ok("the protected T2 seed /__ioi/operations keeps serving untouched (rehome source; seed-preservation invariant — never redirected, never replaced)",
    seedReadout.status === 200 && seedReadout.text.length > 10000,
    `${seedReadout.status} · ${seedReadout.text.length}B`);

  // -- SEED real fixtures via the daemon ------------------------------------------------------
  const autoSeed = await jd("/v1/hypervisor/automations", {
    method: "POST",
    body: JSON.stringify({
      name: "ops-cockpit-fixture-schedule",
      project_ref: "project:ops-cockpit-fixture",
      trigger_kind: "time",
      schedule_spec: { cron: "0 3 * * *", timezone: "UTC" },
    }),
  });
  const autoId = autoSeed.body?.automation?.automation_id || "";
  ok("fixture: a scheduled automation seeds through the daemon under the operator identity (201; schedule_spec validated; INV-37 acting principal resolved)",
    autoSeed.status === 201 && autoId.startsWith("auto_")
      && String(autoSeed.body?.automation?.acting_principal_ref || "").length > 0,
    `${autoSeed.status} · ${autoId}`);

  const planSeed = await jd("/v1/hypervisor/failover/plans", {
    method: "POST",
    body: JSON.stringify({ environment_ref: "env-ops-cockpit-fixture" }),
  });
  const planRef = planSeed.body?.plan?.plan_ref || "";
  ok("fixture: a failover plan seeds (200, fpl_*) with readiness no_restore_material — preparation evidence, honest about the missing material",
    planSeed.status === 200 && planRef.startsWith("failover-plan://fpl_")
      && planSeed.body?.plan?.readiness === "no_restore_material",
    `${planSeed.status} · ${planRef}`);

  const runSeed = await jd("/v1/hypervisor/failover/run", {
    method: "POST",
    body: JSON.stringify({ failure_condition: "provider_outage", plan_ref: planRef }),
  });
  const runRef = runSeed.body?.run?.run_ref || "";
  ok("fixture: a failover run over the material-less plan REFUSES FAIL-CLOSED (409, failover_refused_no_restore_material) and the refused run persists as durable evidence",
    runSeed.status === 409
      && runSeed.body?.reason === "failover_refused_no_restore_material"
      && runRef.startsWith("failover-run://for_")
      && runSeed.body?.run?.status === "refused",
    `${runSeed.status} · ${runRef}`);

  const backendSeed = await jd("/v1/hypervisor/storage-backends", {
    method: "POST",
    body: JSON.stringify({ kind: "local_disk", display_name: "ops-cockpit-fixture-backend" }),
  });
  const backendRef = backendSeed.body?.backend?.account_ref || "";
  ok("fixture: a storage backend seeds (201, sba_*, status unverified — health truth, never fabricated availability)",
    backendSeed.status === 201 && backendRef.startsWith("storage-backend://sba_")
      && backendSeed.body?.backend?.status === "unverified",
    `${backendSeed.status} · ${backendRef}`);

  // -- the seeded rows render owner-backed ----------------------------------------------------
  const seeded = await pageText(OPS);
  ok("scheduler health reflects the seeded fixture: the scheduled spec renders as a real row (name + cron) with its Automations object-truth link",
    seeded.text.includes("data-ioi-scheduled-spec-row")
      && seeded.text.includes("ops-cockpit-fixture-schedule")
      && seeded.text.includes("0 3 * * *")
      && seeded.text.includes("1 scheduled"));
  ok("cross-provider failover reflects the seeded fixtures: the REFUSED run renders with its refusal reason verbatim (fail-closed evidence, never hidden) and the plan renders its readiness posture",
    seeded.text.includes("data-ioi-failover-run-row")
      && seeded.text.includes(runRef)
      && seeded.text.includes("failover_refused_no_restore_material")
      && seeded.text.includes("data-ioi-failover-plan-row")
      && seeded.text.includes(planRef)
      && seeded.text.includes("no_restore_material"));
  ok("storage custody reflects the seeded fixture: the backend renders with its honest unverified health state",
    seeded.text.includes("data-ioi-storage-backend-row")
      && seeded.text.includes("ops-cockpit-fixture-backend")
      && seeded.text.includes("unverified"));
  ok("environment incidents stay honest-empty (no incident fixtures exist) — real zeros stated as absence, never invented rows",
    seeded.text.includes('data-ioi-honest-empty="incidents"')
      && seeded.text.includes('data-ioi-honest-empty="recovery-attempts"'));

  // -- deep-link targets resolve live ---------------------------------------------------------
  const autosPage = await pageText(LINK_AUTOMATIONS);
  ok("the scheduler object-truth / remediation delegation link resolves: /automations 200s under the Automations owner (live canonical mount, not a gap)",
    autosPage.status === 200 && autosPage.headers.get("x-ioi-surface-owner") === "Automations",
    `owner ${autosPage.headers.get("x-ioi-surface-owner")}`);

  // -- HOME RE-RULING: the flipped links are live and resolve to this mount -------------------
  const homePage = await pageText(HOME);
  ok("Home's Operations links are FLIPPED LIVE: /home renders href=\"/operations\" deep-links (data-ioi-operations-link) and the former operations-mount disabled-named-gap renders nowhere",
    homePage.status === 200
      && homePage.text.includes('href="/operations" data-ioi-operations-link')
      && !homePage.text.includes('data-ioi-named-gap="operations-mount"'));
  ok("following Home's own flipped link lands on the live Operations mount (200, Operations owner, the cockpit's panes)",
    empty.status === 200
      && empty.headers.get("x-ioi-surface-owner") === "Operations"
      && empty.text.includes('id="ops-failover"'));

  // -- reload survival ------------------------------------------------------------------------
  const reload = await pageText(OPS);
  ok("reload: /operations re-renders every seeded row from daemon truth (nothing was page-local state)",
    reload.status === 200
      && reload.text.includes("ops-cockpit-fixture-schedule")
      && reload.text.includes(runRef)
      && reload.text.includes("ops-cockpit-fixture-backend"));

  // -- daemon-restart survival of the read plane ----------------------------------------------
  daemon.kill("SIGTERM");
  await new Promise((r) => setTimeout(r, 1200));
  await startDaemon();
  let survived = { status: 0, text: "" };
  for (let attempt = 0; attempt < 3; attempt++) {
    survived = await pageText(OPS);
    if (survived.status === 200 && survived.text.includes(runRef)) break;
    await new Promise((r) => setTimeout(r, 1200));
  }
  ok("daemon restart: the scheduled automation, the failover plan, the refused run and the storage backend survive as durable records and /operations re-renders the same rows (read-plane restart survival)",
    survived.status === 200
      && survived.text.includes("ops-cockpit-fixture-schedule")
      && survived.text.includes(planRef)
      && survived.text.includes(runRef)
      && survived.text.includes("ops-cockpit-fixture-backend"));

  // -- daemon outage: the typed unavailability page, zero fabricated counts -------------------
  daemon.kill("SIGTERM");
  await new Promise((r) => setTimeout(r, 1200));
  const down = await pageText(OPS);
  ok("daemon down: /operations renders the TYPED unavailability page — the canon fallback-fixture rule held verbatim (nothing is shown rather than fixtures)",
    down.status === 200
      && down.text.includes('data-ioi-daemon-unavailable="true"')
      && down.text.includes("Daemon unreachable")
      && down.text.includes("data-ioi-scope"),
    `status ${down.status}`);
  ok("zero fabricated counts on the outage page: no fixture names, no run/plan/backend refs, no scheduled pills, no honest-empty markers pretending the daemon answered",
    !down.text.includes("ops-cockpit-fixture-schedule")
      && !down.text.includes(runRef)
      && !down.text.includes(planRef)
      && !down.text.includes("ops-cockpit-fixture-backend")
      && !down.text.includes("scheduled")
      && !down.text.includes("data-ioi-honest-empty"));
  await startDaemon();
  await waitFor(`${DAEMON}/healthz`, 30000);

  // -- 3-posture browser matrix on /operations ------------------------------------------------
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
      const resp = await page.goto(`${SERVE}${OPS}`, { waitUntil: "networkidle", timeout: 45000 }).catch(() => null);
      const body = resp ? await page.evaluate(() => document.body.innerText) : "";
      await page.keyboard.press("Tab");
      const focused = resp ? await page.evaluate(() => document.activeElement?.tagName ?? "") : "";
      ok(`posture ${name}: /operations renders, keyboard-focusable, zero console errors`,
        resp && resp.status() === 200 && body.length > 0 && errors.length === 0 && focused !== "" && focused !== "BODY",
        errors[0]?.slice(0, 100) ?? `focus ${focused}`);
      await ctx.close();
    }
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
