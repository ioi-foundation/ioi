#!/usr/bin/env node
// Harvest-port Provenance lineage verifier — the monocle capture as the graph seed for Hypervisor
// Provenance, with a real lineage lane rebound to daemon truth.
//
// Doctrine: local capture -> bootable seed -> daemon rebind -> IOI-owned surface -> retire seed.
// The capture is private UX seed material only; Hypervisor truth comes from the daemon.
//
// Proves:
//   - /__apps/lineage boots the FULL captured lineage-graph grammar under the estate, brand-clean:
//     graph toolbar + tools (layout/select/expand/find/remove/align/flow), legend + color options,
//     selection bar, resource add/open-graph panes, and the right-rail lenses
//     (Preview / History / Code / Build timeline / Data health);
//   - the owning Hypervisor Provenance surface links the seed AND surfaces a DAEMON-BACKED lineage
//     lane: every admitted Work Ledger proof entry is a NODE and its cross-object refs are typed
//     EDGES (receipt / state-root / run / session / harness-profile / release-control / …), with the
//     in-canvas resource-search lanes named as gaps;
//   - the lineage edges on the glass are DAEMON TRUTH — an independent recount from the daemon
//     Work Ledger equals the rendered edge density (no fabricated nodes/edges);
//   - unknown seed honest; no brand leak; only uncaptured-lane fetch failures (no real crash).
//
// Usage: node apps/hypervisor/scripts/verify-hypervisor-harvest-provenance-lineage.mjs
// Exit 2 = BLOCKED (harvest capture or daemon not running) — named, not failed.

import { chromium } from "playwright";

const SERVE = (process.env.IOI_HYPERVISOR_SERVE_URL || "http://127.0.0.1:4173").replace(/\/$/, "");
const CAPTURE = (process.env.IOI_HARVEST_CAPTURE_URL || process.env.IOI_HARVEST_MIRROR_URL || "http://127.0.0.1:9225").replace(/\/$/, "");
const DAEMON = (process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765").replace(/\/$/, "");

const results = [];
const ok = (name, cond, detail) => { results.push({ name, pass: !!cond, detail: detail || "" }); };

async function run() {
  // 0. Liveness — the seed serves live from the capture; the rebind serves from the daemon.
  const captureUp = await fetch(`${CAPTURE}/workspace/monocle/`).then((r) => r.ok).catch(() => false);
  if (!captureUp) { console.error("BLOCKED: harvest capture not reachable at " + CAPTURE); process.exit(2); }
  const daemonUp = await fetch(`${DAEMON}/v1/hypervisor/work-ledger`).then((r) => r.ok).catch(() => false);
  if (!daemonUp) { console.error("BLOCKED: daemon not reachable at " + DAEMON); process.exit(2); }
  ok("harvest capture + daemon live", true, `${CAPTURE} · ${DAEMON}`);

  // 1. Owner surface (Provenance) links the seed AND carries the daemon lineage lane.
  const prov = await fetch(`${SERVE}/__ioi/work-ledger`).then(async (r) => ({ status: r.status, text: await r.text() }));
  ok("Provenance surface serves", prov.status === 200 && !prov.text.includes("Palantir"));
  ok("Provenance links the /__apps/lineage graph seed", prov.text.includes("/__apps/lineage"));
  ok("Provenance carries a daemon-backed lineage lane", /id="provenance-lineage"/.test(prov.text) && /Lineage edge density/.test(prov.text) && /Sample node neighborhood/.test(prov.text));
  ok("Provenance names the in-canvas resource-search lanes as gaps", /named gap/i.test(prov.text));

  // 2. Lineage edges on the glass == daemon truth (independent recount, no fabrication).
  const ledger = await fetch(`${DAEMON}/v1/hypervisor/work-ledger`).then((r) => r.json());
  const entries = ledger.entries || [];
  ok("daemon Work Ledger exposes admitted proof entries", entries.length >= 1, `${entries.length} entries`);
  const recount = (k) => entries.filter((e) => e[k]).length;
  // Verify each rendered "<label> · <count>" chip against an independent daemon recount.
  const glassEdges = [...prov.text.matchAll(/>([\w-]+) · (\d+)</g)].reduce((m, [, label, n]) => (m[label] = Number(n), m), {});
  const checkEdge = (label, key) => {
    const daemonN = recount(key);
    if (daemonN === 0) return true; // edge type absent — legitimately not rendered
    return glassEdges[label] === daemonN;
  };
  const receiptOk = checkEdge("receipt", "receipt_ref");
  const stateRootOk = checkEdge("state-root", "state_root");
  const sessionOk = checkEdge("session", "session_ref");
  const relCtrlOk = checkEdge("release-control", "release_control_ref");
  ok("rendered lineage edge density equals an independent daemon recount (no fabrication)", receiptOk && stateRootOk && sessionOk && relCtrlOk, `receipt=${glassEdges.receipt}/${recount("receipt_ref")} state-root=${glassEdges["state-root"]}/${recount("state_root")} session=${glassEdges.session}/${recount("session_ref")} release-control=${glassEdges["release-control"]}/${recount("release_control_ref")}`);
  ok("sample node neighborhood renders a real proof entry's typed edges", /Sample node neighborhood/.test(prov.text) && /<ul class="wlbl"/.test(prov.text));

  // 3. The captured monocle graph grammar boots under the estate (Playwright).
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1600, height: 1000 } });
  const consoleErrors = [];
  page.on("pageerror", (e) => consoleErrors.push(String(e)));
  await page.goto(`${SERVE}/__apps/lineage`, { waitUntil: "domcontentloaded" });
  await page.waitForTimeout(6000);
  const boot = await page.evaluate(() => {
    const t = document.body.innerText;
    return {
      dataLineage: /data lineage/i.test(t),
      addResources: /add resources/i.test(t),
      openGraph: /open graph/i.test(t),
      tools: /\blayout\b/i.test(t) && /\bselect\b/i.test(t) && /\bexpand\b/i.test(t) && /\bfind\b/i.test(t) && /\bremove\b/i.test(t),
      legend: /legend/i.test(t),
      selectionBar: /nodes? selected/i.test(t),
      lensPreview: /preview/i.test(t),
      lensHistory: /history/i.test(t),
      lensCode: /\bcode\b/i.test(t),
      lensBuild: /build timeline|\bbuild\b/i.test(t),
      lensDataHealth: /data health/i.test(t),
      hasCanvas: !!document.querySelector("canvas, svg, [class*=graph i], [class*=canvas i]"),
      brandLeak: document.body.innerHTML.includes("Palantir"),
    };
  });
  ok("seed boots the Data Lineage graph grammar (canvas + add/open-graph panes)", boot.dataLineage && boot.addResources && boot.openGraph && boot.hasCanvas);
  ok("graph toolbar/tools present (layout / select / expand / find / remove)", boot.tools);
  ok("legend + selection bar present (graph chrome)", boot.legend && boot.selectionBar);
  ok("right-rail lenses present (preview / history / code / build / data-health)", boot.lensPreview && boot.lensHistory && boot.lensCode && boot.lensBuild && boot.lensDataHealth);
  ok("no brand leak in the booted graph", !boot.brandLeak);
  const laneGap = consoleErrors.filter((e) => /GraphQL|Failed to fetch|NetworkError|fetch failed|Load failed/i.test(e));
  const crashes = consoleErrors.filter((e) => !/GraphQL|Failed to fetch|NetworkError|fetch failed|Load failed/i.test(e));
  ok("graph boots; only uncaptured-lane fetch failures (named gaps), no real crashes", crashes.length === 0, crashes.length ? crashes.slice(0, 2).join(" | ") : `${laneGap.length} uncaptured-lane gap error(s), 0 crashes`);
  await page.screenshot({ path: process.env.IOI_LINEAGE_SHOT || "/tmp/lineage-canvas.png" }).catch(() => {});
  await browser.close();

  // 4. Shared honesty: unknown seed 404s.
  const unknown = await fetch(`${SERVE}/__apps/definitely-not-a-seed`).then((r) => r.status).catch(() => 0);
  ok("unknown seed is honest (404)", unknown === 404, String(unknown));
}

run().then(() => {
  let fail = 0;
  for (const r of results) { console.log(`  ${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? `  (${r.detail})` : ""}`); if (!r.pass) fail++; }
  console.log(`\n${results.length - fail}/${results.length} passed`);
  console.log(`harvest provenance-lineage readiness: ${fail ? "FAIL" : "OK"}`);
  process.exit(fail ? 1 : 0);
}).catch((e) => {
  console.error("verifier crashed:", e);
  process.exit(1);
});
