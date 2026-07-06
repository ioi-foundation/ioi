#!/usr/bin/env node
// Harvest-port approvals verifier — PHASE 2 (REBOUND): the seed's task-request search lanes are
// answered with DAEMON approval-requests, not capture fixtures.
//
// Proves: the bootable capture artifact serves under the estate (/__apps/approvals, live wire
// proxy — nothing harvested enters the repo) with brand-cased strings rebranded at the wire;
// the seed's search/counts lanes return EXACTLY the daemon's approval-requests mapped into the
// seed's wire shape (every daemon id present, nothing fabricated, identity-scoped subcounts
// honestly 0); a fresh daemon fixture round-trips into the BOOTED premium inbox UI; and the
// offline state stays honest. Named gaps (vendor-phase work): per-row drilldown lanes still
// pass through to the capture; the seed's closed type registry renders our rows under its
// closest category ("access request" = request for authority over a resource) — every rendered
// FACT is daemon truth.
//
// Usage: node apps/hypervisor/scripts/verify-hypervisor-harvest-approvals.mjs
// Exit 2 = BLOCKED (harvest capture or daemon not running) — named, not failed.

import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { chromium } from "playwright";

const HERE = dirname(fileURLToPath(import.meta.url));
const SERVE = (process.env.IOI_HYPERVISOR_SERVE_URL || "http://127.0.0.1:4173").replace(/\/$/, "");
const CAPTURE = (process.env.IOI_HARVEST_CAPTURE_URL || process.env.IOI_HARVEST_MIRROR_URL || "http://127.0.0.1:9225").replace(/\/$/, "");
const DAEMON = (process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765").replace(/\/$/, "");

const results = [];
const ok = (name, cond, detail) => { results.push({ name, pass: !!cond, detail: detail || "" }); };

async function run() {
  // 0. Liveness — the seed document serves live from the capture; the rebind serves from the
  // daemon. Absence of either is a BLOCK, not a failure.
  const captureUp = await fetch(`${CAPTURE}/workspace/approvals-app/`).then((r) => r.ok).catch(() => false);
  if (!captureUp) {
    console.error("BLOCKED: harvest capture not reachable at " + CAPTURE + " — start internal-docs/reverse-engineering/palantir/server.js");
    process.exit(2);
  }
  const daemonUp = await fetch(`${DAEMON}/v1/hypervisor/governance/approval-requests`).then((r) => r.ok).catch(() => false);
  if (!daemonUp) {
    console.error("BLOCKED: daemon not reachable at " + DAEMON);
    process.exit(2);
  }
  ok("harvest capture + daemon live", true, `${CAPTURE} · ${DAEMON}`);

  // 1. Served under the estate, rebranded at the wire.
  const page1 = await fetch(`${SERVE}/__apps/approvals`).then(async (r) => ({ status: r.status, ct: r.headers.get("content-type") || "", text: await r.text() }));
  ok("seed serves under the estate", page1.status === 200 && page1.ct.includes("text/html"));
  ok("brand-cased strings rebranded at the wire", !page1.text.includes("Palantir"), "code tokens defer to the vendor phase");
  ok("unknown seed is honest", (await fetch(`${SERVE}/__apps/nonesuch`).then((r) => r.status)) === 404);

  // 2. Fixture: a fresh PENDING approval-request in the daemon (real object, clearly labeled).
  const fixtureReason = `verify-approvals-rebind ${Date.now().toString(36)}`;
  const created = await fetch(`${DAEMON}/v1/hypervisor/governance/approval-requests`, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ subject_ref: "verify://harvest-approvals-rebind", request_kind: "verify_rebind", reason: fixtureReason }),
  }).then((r) => r.json()).catch(() => null);
  const fixtureId = created?.approval_request?.id || created?.id;
  ok("daemon fixture approval-request created", !!fixtureId, fixtureId);

  // 3. REBOUND WIRE — the search lane returns exactly the daemon's rows, in the seed's shape.
  const daemonList = await fetch(`${DAEMON}/v1/hypervisor/governance/approval-requests`).then((r) => r.json());
  const daemonRows = daemonList.approval_requests || [];
  const search = await fetch(`${SERVE}/approvals/api/search/task-requests`, {
    method: "PUT", headers: { "content-type": "application/json" },
    body: JSON.stringify({ sort: { field: "CREATION_TIME", order: "DESC" } }),
  }).then((r) => r.json());
  const wireRids = new Set((search.requests || []).map((r) => r.taskRid));
  ok("search lane carries EVERY daemon approval-request", daemonRows.every((d) => wireRids.has(`ri.approvals.main.task-request.${d.id}`)), `${daemonRows.length} daemon rows`);
  ok("search lane fabricates NOTHING", (search.requests || []).every((r) => daemonRows.some((d) => r.taskRid.endsWith(d.id))), `${wireRids.size} wire rows`);
  const fixtureRow = (search.requests || []).find((r) => r.taskRid.endsWith(fixtureId));
  ok("fixture mapped with real kind + reason in title and PENDING_APPROVAL status", !!fixtureRow && fixtureRow.title.includes("verify_rebind") && fixtureRow.title.includes(fixtureReason) && fixtureRow.status === "PENDING_APPROVAL");

  // 4. Counts lane — totals are daemon truth; identity-scoped tab honestly 0 (daemon records no creator).
  const counts = await fetch(`${SERVE}/approvals/api/search/task-requests/counts`, {
    method: "PUT", headers: { "content-type": "application/json" }, body: "{}",
  }).then((r) => r.json());
  ok("counts lane totals match the daemon", counts.totalCount === daemonRows.length, `${counts.totalCount} vs ${daemonRows.length}`);
  ok("identity-scoped subcount honestly 0 (no creator identity in daemon)", counts.subCounts && counts.subCounts.myRequests === 0);

  // 5. The BOOTED premium inbox renders the fixture (daemon truth on the glass).
  const b = await chromium.launch();
  try {
    const page = await b.newPage({ viewport: { width: 1600, height: 1000 } });
    await page.goto(`${SERVE}/__apps/approvals`, { waitUntil: "networkidle", timeout: 60000 }).catch(() => {});
    await page.waitForTimeout(7000);
    const state = await page.evaluate(() => ({
      text: (document.body.innerText || "").replace(/\s+/g, " "),
      buttons: document.querySelectorAll("button, [role=button]").length,
    }));
    ok("app boots with its real inbox UI", /Your inbox|All requests/.test(state.text) && state.buttons > 5, `${state.buttons} controls`);
    ok("fixture renders IN the booted UI (title carries daemon kind + reason)", state.text.includes("verify_rebind") && state.text.includes(fixtureReason));
    ok("no brand-cased strings in rendered text", !/Palantir/.test(state.text));
  } finally {
    await b.close();
  }

  // 6. Offline honesty — isolated serve pointed at a dead capture names the outage (the document
  // serves from the capture even though the data lanes are daemon-bound).
  const child = spawn(process.execPath, [join(HERE, "serve-product-ui.mjs")], {
    env: { ...process.env, PORT: "4602", PRODUCT_UI_PORT: "9402", IOI_HARVEST_MIRROR_URL: "http://127.0.0.1:1" },
    stdio: "ignore",
  });
  try {
    let deg = null;
    for (let i = 0; i < 30 && !deg; i++) {
      await new Promise((r) => setTimeout(r, 500));
      deg = await fetch("http://127.0.0.1:4602/__apps/approvals").then(async (r) => ({ status: r.status, text: await r.text() })).catch(() => null);
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
  console.log("harvest-approvals REBIND readiness: OK");
}).catch((e) => { console.error("verifier crashed:", e); process.exit(1); });
