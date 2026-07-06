#!/usr/bin/env node
// Harvest-port canvas-seeds readiness verifier — the first suite-taxonomy adoptions after the
// approvals pilot (suite-guide §9): three highest-leverage canvas seeds served under the estate.
//
//   /__apps/lineage   ← monocle            (Provenance seed — bootable lineage-graph editor)
//   /__apps/designer  ← solution-design    (Studio seed — typed-node system-diagram editor)
//   /__apps/monitors  ← object-monitoring  (Automations seed — condition→effect wizard)
//
// Proves per seed: serves under the estate via the live wire proxy (nothing harvested enters the
// repo), brand-cased strings rebranded at the wire, the app BOOTS to its real editor/landing UI
// through the estate origin, and its owning suite surface links the seed. Plus shared honesty:
// unknown seed 404s, offline mirror names the outage (503, no fabricated app).
//
// Usage: node apps/hypervisor/scripts/verify-hypervisor-harvest-canvas-seeds.mjs
// Exit 2 = BLOCKED (harvest mirror not running) — named, not failed.

import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { chromium } from "playwright";

const HERE = dirname(fileURLToPath(import.meta.url));
const SERVE = (process.env.IOI_HYPERVISOR_SERVE_URL || "http://127.0.0.1:4173").replace(/\/$/, "");
const MIRROR = (process.env.IOI_HARVEST_MIRROR_URL || "http://127.0.0.1:9225").replace(/\/$/, "");

const results = [];
const ok = (name, cond, detail) => { results.push({ name, pass: !!cond, detail: detail || "" }); };

const SEEDS = [
  {
    slug: "lineage", mirror: "/workspace/monocle/", owner: "Provenance",
    ownerUrl: "/__ioi/work-ledger",
    // The monocle editor boots complete: graph toolbar + welcome card + selection status bar.
    boot: (t) => /Add resources|Open graph|Resource overview/.test(t) && /nodes selected|Layout/.test(t),
    bootDesc: "lineage-graph editor (toolbar + Add resources/Open graph + selection bar)",
  },
  {
    slug: "designer", mirror: "/workspace/solution-design/", owner: "Studio",
    ownerUrl: "/__ioi/agent-studio",
    boot: (t) => /Solution Designer|solution design/i.test(t) && /New Diagram|reference example/i.test(t),
    bootDesc: "system-diagram landing (New Diagram + reference-diagram shelf)",
  },
  {
    slug: "monitors", mirror: "/workspace/object-monitoring/", owner: "Automations",
    ownerUrl: "/__ioi/automations",
    boot: (t) => /Automat/i.test(t) && /New automation|Create new automation|Automations/i.test(t),
    bootDesc: "monitor/automation landing (New automation entry)",
  },
];

async function run() {
  // 0. Mirror liveness — seeds serve live from the mirror; absence is a BLOCK, not a failure.
  const mirrorUp = await fetch(`${MIRROR}/workspace/monocle/`).then((r) => r.ok).catch(() => false);
  if (!mirrorUp) {
    console.error("BLOCKED: harvest mirror not reachable at " + MIRROR + " — start internal-docs/reverse-engineering/palantir/server.js");
    process.exit(2);
  }
  ok("harvest mirror live", true, MIRROR);

  const b = await chromium.launch();
  try {
    for (const seed of SEEDS) {
      // 1. Served under the estate, rebranded at the wire.
      const doc = await fetch(`${SERVE}/__apps/${seed.slug}`).then(async (r) => ({ status: r.status, ct: r.headers.get("content-type") || "", text: await r.text() }));
      ok(`[${seed.slug}] seed serves under the estate`, doc.status === 200 && doc.ct.includes("text/html"));
      ok(`[${seed.slug}] brand-cased strings rebranded at the wire`, !doc.text.includes("Palantir"), "code tokens defer to the vendor phase");

      // 2. The app BOOTS through the estate origin.
      const page = await b.newPage({ viewport: { width: 1600, height: 1000 } });
      const api = new Set();
      page.on("request", (r) => {
        const u = r.url();
        if (!u.startsWith(SERVE)) return;
        const p = new URL(u).pathname;
        if (p.startsWith("/assets/") || /\.(js|css|woff2?|png|svg|ico|ttf)$/.test(p) || p.startsWith("/__apps/")) return;
        api.add(r.method() + " " + p.replace(/ri\.[^/]+/g, ":rid").replace(/[a-f0-9-]{20,}/g, ":id"));
      });
      await page.goto(`${SERVE}/__apps/${seed.slug}`, { waitUntil: "networkidle", timeout: 60000 }).catch(() => {});
      await page.waitForTimeout(6000);
      const state = await page.evaluate(() => ({
        text: (document.body.innerText || "").replace(/\s+/g, " "),
        buttons: document.querySelectorAll("button, [role=button]").length,
      }));
      ok(`[${seed.slug}] app boots to its real UI`, seed.boot(state.text) && state.buttons > 5, `${seed.bootDesc}; ${state.buttons} controls`);
      ok(`[${seed.slug}] no brand-cased strings in rendered text`, !/Palantir/.test(state.text));
      console.log(`REBIND MAP [${seed.slug}] — non-asset calls the booted app makes (${api.size}):`);
      [...api].sort().forEach((x) => console.log("  " + x));
      await page.close();

      // 3. The owning suite surface links the seed.
      const owner = await fetch(`${SERVE}${seed.ownerUrl}`).then((r) => r.text());
      ok(`[${seed.slug}] ${seed.owner} links the seed`, owner.includes(`href="/__apps/${seed.slug}"`));
    }
  } finally {
    await b.close();
  }

  // 4. Shared honesty: unknown seed 404s; offline mirror named honestly.
  ok("unknown seed is honest", (await fetch(`${SERVE}/__apps/nonesuch`).then((r) => r.status)) === 404);
  const child = spawn(process.execPath, [join(HERE, "serve-product-ui.mjs")], {
    env: { ...process.env, PORT: "4603", PRODUCT_UI_PORT: "9403", IOI_HARVEST_MIRROR_URL: "http://127.0.0.1:1" },
    stdio: "ignore",
  });
  try {
    let deg = null;
    for (let i = 0; i < 30 && !deg; i++) {
      await new Promise((r) => setTimeout(r, 500));
      deg = await fetch("http://127.0.0.1:4603/__apps/lineage").then(async (r) => ({ status: r.status, text: await r.text() })).catch(() => null);
    }
    ok("offline mirror named honestly (503, no fabricated app)", !!deg && deg.status === 503 && deg.text.includes("Harvest mirror offline"));
  } finally {
    child.kill("SIGTERM");
  }
}

run().then(() => {
  const fails = results.filter((r) => !r.pass);
  for (const r of results) console.log(`${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? ` — ${r.detail}` : ""}`);
  console.log(`\n${results.length - fails.length}/${results.length} passed`);
  if (fails.length) process.exit(1);
  console.log("harvest canvas-seeds readiness: OK");
}).catch((e) => { console.error("verifier crashed:", e); process.exit(1); });
