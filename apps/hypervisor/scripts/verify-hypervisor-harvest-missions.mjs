#!/usr/bin/env node
// Harvest-port Missions verifier — REBIND phase: the fleet seeds' data lanes are answered
// with DAEMON truth, not capture fixtures.
//
// Proves: (1) /__apps/jobs (job-tracker seed) reads its build queue through GraphQL buildsV2
// and the serve answers with the daemon's REAL run estate — work results, sessions (the
// daemon's own newest-50 projection), automation executions — every daemon
// record present by its VERBATIM ref in the Outputs cell, nothing fabricated, identity-scoped
// views honestly empty (the daemon maps no seed-user identity); a session fixture created
// through the daemon's own API round-trips into the BOOTED premium queue UI. (2)
// /__apps/incidents (issues-app seed) searches through /issues/api/search/issues/v2 and the
// serve answers with the daemon's provider-failure incidents — counts are daemon truth,
// identity filters match nothing, and the booted inbox renders real incidents (failure kind +
// environment ref, detection time). Incidents have NO creation lane by design (405) — they
// exist only when the failover machinery records one, so the incident assertions run over the
// records that exist and an empty estate must show an honestly empty inbox.
//
// GoalRun left the Hypervisor (R-192, S5-1; standing owner ruling 2026-09-24). The builds lane's
// first source was the goal-run list; the serve replaced it with recorded WorkResults (named by
// their work subject) in that cut, but this verifier kept reading /v1/goal-orchestration/goal-runs
// — 404, hidden behind the anonymous 401 until the 2026-09-29 auth sweep — and crashed on its
// body. It now checks the lane against /v1/hypervisor/work-results, and the "draft goal-runs are
// not runs" clause is gone with the plane: a WorkResult has no draft state (R-240, sweep findings,
// 2026-09-29).
//
// Usage: node apps/hypervisor/scripts/verify-hypervisor-harvest-missions.mjs
// Exit 2 = BLOCKED (harvest capture or daemon not running) — named, not failed.

import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { chromium } from "playwright";

const HERE = dirname(fileURLToPath(import.meta.url));
// Its own isolated daemon (+ serve), the operator signed in (R-240, verifier auth sweep, 2026-09-29). This verifier read
// `IOI_HYPERVISOR_DAEMON_URL || :8765` — the OWNER's daemon — with no caller; since 3aaaad467/3738d5cab the data-source,
// materialized-set and ontology reads answer an anonymous caller 401 (read here as "not reachable"), and since 90cd1ddf2
// an anonymous write is refused on loopback too. An explicit URL naming the owner's stack is refused (verifier-stack.mjs).
import { verifierStack } from "./lib/verifier-stack.mjs";
const STACK = await verifierStack({ serve: true });
STACK.addOrigin("http://127.0.0.1:4612"); // its own mirror-down serve (below) reads the same daemon as the same operator
const SERVE = STACK.serveUrl;
const CAPTURE = (process.env.IOI_HARVEST_CAPTURE_URL || process.env.IOI_HARVEST_MIRROR_URL || "http://127.0.0.1:9225").replace(/\/$/, "");
const DAEMON = STACK.daemonUrl;

const results = [];
const ok = (name, cond, detail) => { results.push({ name, pass: !!cond, detail: detail || "" }); };

const buildsQuery = (filter) => ({
  operationName: "OverviewPageQuery",
  variables: { pageSize: 500, filter: [filter], sortType: "BY_STARTED_TIME", sortDirection: "DESCENDING" },
  query: "query OverviewPageQuery($pageSize: Int!, $pageToken: String, $filter: [BuildFilterInput!]!, $sortType: JobTrackerSortType!, $sortDirection: SortDirection!) { buildsV2(pageSize: $pageSize, pageToken: $pageToken, filter: $filter, sortType: $sortType, sortDirection: $sortDirection) { values nextPageToken } }",
});
const emptyFilter = { userIds: [], outputRids: [], branches: [], excludedBranches: [], jobOutputRids: [], buildRids: [], buildInputRids: [], jobTypes: [], excludedJobTypes: [], transformTypes: [], excludedTransformTypes: [], buildStatuses: ["CANCELED", "FAILED", "RUNNING", "SUCCEEDED", "FAILED_TO_START"] };
const postBuilds = (filter) => fetch(`${SERVE}/graphql-gateway/api/graphql?q=OverviewPageQuery`, {
  method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(buildsQuery(filter)),
}).then((r) => r.json());

async function run() {
  // 0. Liveness — seeds serve live from the capture; rebinds serve from the daemon.
  const captureUp = await fetch(`${CAPTURE}/workspace/job-tracker/`).then((r) => r.ok).catch(() => false);
  if (!captureUp) { console.error("BLOCKED: harvest capture not reachable at " + CAPTURE); process.exit(2); }
  await STACK.requireRead(`/v1/hypervisor/sessions`, "the daemon");
  ok("harvest capture + daemon live", true, `${CAPTURE} · ${DAEMON}`);

  // 1. Both seeds serve under the estate, rebranded at the wire.
  for (const slug of ["jobs", "incidents"]) {
    const page = await fetch(`${SERVE}/__apps/${slug}`).then(async (r) => ({ status: r.status, text: await r.text() }));
    ok(`[${slug}] seed serves under the estate`, page.status === 200 && !page.text.includes("Palantir"));
  }

  // 2. Session fixture through the daemon's own API (a REAL provisioned session).
  const before = await fetch(`${DAEMON}/v1/hypervisor/sessions`).then((r) => r.json());
  const beforeRefs = new Set((before.sessions || []).map((s) => s.session_ref));
  await fetch(`${DAEMON}/v1/hypervisor/sessions`, { method: "POST", headers: { "content-type": "application/json" }, body: "{}" });
  await new Promise((r) => setTimeout(r, 1500));
  const after = await fetch(`${DAEMON}/v1/hypervisor/sessions`).then((r) => r.json());
  const fixtureRef = (after.sessions || []).map((s) => s.session_ref).find((ref) => !beforeRefs.has(ref));
  ok("daemon session fixture created", !!fixtureRef, fixtureRef);

  // 3. REBOUND WIRE (jobs) — the builds lane carries the daemon's run estate verbatim.
  const [wrj, ssj, atj] = await Promise.all([
    fetch(`${DAEMON}/v1/hypervisor/work-results`).then((r) => r.json()),
    fetch(`${DAEMON}/v1/hypervisor/sessions`).then((r) => r.json()),
    fetch(`${DAEMON}/v1/hypervisor/automations`).then((r) => r.json()),
  ]);
  const autoRuns = (await Promise.all((atj.automations || []).map((a) => fetch(`${DAEMON}/v1/hypervisor/automations/${encodeURIComponent(a.automation_id)}/runs`).then((r) => r.json()).catch(() => ({}))))).flatMap((r) => r.runs || []);
  const wire = await postBuilds(emptyFilter);
  const rows = wire?.data?.buildsV2?.values || [];
  const names = new Set(rows.map((r) => r.outputs?.values?.[0]?.name));
  // The serve names a work-result row by its work subject (or its id), cut to 64 characters.
  const resultNames = (wrj.work_results || []).map((r) => String(r.work_subject_ref || String(r.work_result_id || "").replace(/^work-result:\/\//, "")).slice(0, 64));
  const sessRefs = (ssj.sessions || []).map((s) => s.session_ref);
  const execIds = autoRuns.map((x) => x.execution_id);
  ok("every daemon work result on the wire", resultNames.every((n) => names.has(n)), `${resultNames.length} work results`);
  ok("every daemon session on the wire (daemon's newest-50 projection)", sessRefs.every((s) => names.has(s)), `${sessRefs.length} sessions`);
  ok("every automation execution on the wire", execIds.every((x) => names.has(x)), `${execIds.length} executions`);
  const known = new Set([...resultNames, ...sessRefs, ...execIds]);
  ok("jobs lane fabricates NOTHING", rows.every((r) => known.has(r.outputs?.values?.[0]?.name)), `${rows.length} wire rows`);
  ok("fixture session on the wire", names.has(fixtureRef));
  const fixtureRow = rows.find((r) => r.outputs?.values?.[0]?.name === fixtureRef);
  ok("fixture carries real state (provisioned → RUNNING, no invented finish time)", !!fixtureRow && fixtureRow.status === "RUNNING" && fixtureRow.finishedAt === null);

  // 4. Identity honesty — a userIds-scoped view carries no rows (no identity mapping yet).
  const scoped = await postBuilds({ ...emptyFilter, userIds: ["fe77707c-1590-4b15-9dca-9f92e943d79d"] });
  ok("identity-scoped view honestly empty", (scoped?.data?.buildsV2?.values || []).length === 0);

  // 5. REBOUND WIRE (incidents) — the issues search carries the daemon's incidents.
  const ij = await fetch(`${DAEMON}/v1/hypervisor/incidents`).then((r) => r.json());
  const incs = ij.incidents || [];
  const search = await fetch(`${SERVE}/issues/api/search/issues/v2/search`, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ aggregations: {}, count: 100, filters: [{ archived: "NOT_ARCHIVED", type: "archived" }], from: 0, sort: { direction: "DESC", field: "UPDATED_AT" } }),
  }).then((r) => r.json());
  const hitTitles = (search.hits || []).map((h) => h.value.title);
  ok("every daemon incident on the wire (kind + environment verbatim)", incs.every((i) => hitTitles.some((t) => t.includes(i.failure_kind) && t.includes(i.environment_ref))), `${incs.length} incidents`);
  ok("incidents lane fabricates NOTHING", (search.hits || []).every((h) => incs.some((i) => h.value.title.includes(i.environment_ref))), `${search.hitCount} wire hits`);
  ok("incident status maps by closest category (recovered→CLOSED, else OPEN)", (search.hits || []).every((h) => { const i = incs.find((x) => h.value.title.includes(x.environment_ref)); return i && h.value.status === (i.status === "recovered" ? "CLOSED" : "OPEN"); }));
  ok("no update time invented (both records carry the detection time)", (search.hits || []).every((h) => h.value.attribution.time === h.value.lastUpdateAttribution.time));
  const batch = await fetch(`${SERVE}/issues/api/search/issues/v2/batch`, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify([{ aggregations: { totalClosedCount: { field: "ISSUE_ID", filters: [{ status: { include: ["CLOSED"], type: "include" }, type: "status" }] }, totalOpenCount: { field: "ISSUE_ID", filters: [{ status: { exclude: ["CLOSED"], type: "exclude" }, type: "status" }] } }, count: 40, filters: [{ archived: "NOT_ARCHIVED", type: "archived" }], from: 0, sort: { direction: "DESC", field: "UPDATED_AT" } }]),
  }).then((r) => r.json());
  const agg = batch?.[0]?.aggregations || {};
  const wantClosed = incs.filter((i) => i.status === "recovered").length;
  ok("incident counts are daemon truth", agg.totalClosedCount?.value === wantClosed && agg.totalOpenCount?.value === incs.length - wantClosed, `closed ${agg.totalClosedCount?.value}/${wantClosed}`);
  const reporterScoped = await fetch(`${SERVE}/issues/api/search/issues/v2/search`, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ aggregations: {}, count: 100, filters: [{ reporter: { reporters: ["fe77707c-1590-4b15-9dca-9f92e943d79d"] }, type: "reporter" }], from: 0, sort: { direction: "DESC", field: "UPDATED_AT" } }),
  }).then((r) => r.json());
  ok("incident identity filters honestly empty", (reporterScoped.hits || []).length === 0);

  // 6. BOOTED UIs — daemon truth on the glass.
  const b = await chromium.launch();
  try {
    const page = await b.newPage({ viewport: { width: 1700, height: 1000 } });
    await STACK.signIn(page);
    await page.goto(`${SERVE}/__apps/jobs`, { waitUntil: "networkidle", timeout: 60000 }).catch(() => {});
    await page.waitForTimeout(7000);
    const dflt = await page.evaluate(() => (document.body.innerText || "").replace(/\s+/g, " "));
    ok("[jobs] identity-scoped default view honestly empty", dflt.includes("No visible builds"));
    await page.locator('button:has-text("Clear all filters")').first().click().catch(() => {});
    await page.waitForTimeout(7000);
    const text = await page.evaluate(() => (document.body.innerText || "").replace(/\s+/g, " "));
    ok("[jobs] booted queue renders the daemon estate (work-result + session + automation rows; no goal runs)", !text.includes("goal://gr_") && (resultNames.length === 0 || resultNames.some((n) => text.includes(n))) && (sessRefs.length === 0 || /session:/.test(text)) && (execIds.length === 0 || text.includes("aex_")));
    ok("[jobs] fixture session renders IN the booted UI", !fixtureRef || text.includes(fixtureRef));
    ok("[jobs] automation attribution renders (started by automation name)", execIds.length === 0 || (atj.automations || []).some((a) => a.name && text.includes(a.name)));
    ok("[jobs] no brand-cased strings in rendered text", !/Palantir/.test(text));

    const page2 = await b.newPage({ viewport: { width: 1700, height: 1000 } });

    await STACK.signIn(page2);
    await page2.goto(`${SERVE}/__apps/incidents`, { waitUntil: "networkidle", timeout: 60000 }).catch(() => {});
    await page2.waitForTimeout(6000);
    if (incs.length) {
      await page2.locator("text=Closed").first().click().catch(() => {});
      await page2.waitForTimeout(5000);
    }
    const itext = await page2.evaluate(() => (document.body.innerText || "").replace(/\s+/g, " "));
    ok("[incidents] booted inbox carries daemon counts", incs.length === 0 ? /Open 0/.test(itext) : new RegExp(`All ${incs.length}`).test(itext));
    ok("[incidents] real incidents render (failure kind + environment ref)", incs.length === 0 || incs.every((i) => itext.includes(`${i.failure_kind} · ${i.environment_ref}`)));
    ok("[incidents] no brand-cased strings in rendered text", !/Palantir/.test(itext));
  } finally {
    await b.close();
  }

  // 7. Offline honesty — a serve pointed at a dead capture names the outage.
  const child = spawn(process.execPath, [join(HERE, "serve-product-ui.mjs")], {
    env: { ...STACK.childEnv(), PORT: "4612", PRODUCT_UI_PORT: "9412", IOI_HARVEST_MIRROR_URL: "http://127.0.0.1:1" },
    stdio: "ignore",
  });
  try {
    let deg = null;
    for (let i = 0; i < 30 && !deg; i++) {
      await new Promise((r) => setTimeout(r, 500));
      deg = await fetch("http://127.0.0.1:4612/__apps/jobs").then(async (r) => ({ status: r.status, text: await r.text() })).catch(() => null);
    }
    ok("offline capture named honestly (503, no fabricated app)", !!deg && deg.status === 503 && deg.text.includes("Harvest capture offline"));
  } finally {
    child.kill("SIGTERM");
  }
}

run().then(() => {
  const fails = results.filter((r) => !r.pass);
  for (const r of results) console.log(`${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? ` — ${r.detail}` : ""}`);
  console.log(`\n${results.length - fails.length}/${results.length} passed`);
  if (fails.length) process.exit(1);
  console.log("harvest-missions REBIND readiness: OK");
  process.exit(0); // its own stack (daemon + serve children) would otherwise keep the process alive
}).catch((e) => { console.error("verifier crashed:", e); process.exit(1); });
