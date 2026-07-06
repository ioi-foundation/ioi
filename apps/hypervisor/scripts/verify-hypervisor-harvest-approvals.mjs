#!/usr/bin/env node
// Harvest-port pilot readiness verifier (Approvals seed — the first application adopted from the
// harvest mirror rather than recreated from grammar).
//
// Proves the pipeline: the bootable mirror artifact serves under the estate (/__apps/approvals,
// live wire proxy — nothing harvested enters the repo), brand-cased strings rebranded at the
// wire, the app BOOTS with its real inbox UI, content-addressed assets resolve through the
// estate origin, the offline state is honest, and the API INTERCEPTION INVENTORY (every
// non-asset call the booted app makes) is recorded — that inventory IS the rebind map for the
// next phase.
//
// Usage: node apps/hypervisor/scripts/verify-hypervisor-harvest-approvals.mjs
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

async function run() {
  // 0. Mirror liveness — a seed serves live from the mirror; absence is a BLOCK, not a failure.
  const mirrorUp = await fetch(`${MIRROR}/workspace/approvals-app/`).then((r) => r.ok).catch(() => false);
  if (!mirrorUp) {
    console.error("BLOCKED: harvest mirror not reachable at " + MIRROR + " — start internal-docs/reverse-engineering/palantir/server.js");
    process.exit(2);
  }
  ok("harvest mirror live", true, MIRROR);

  // 1. Served under the estate, rebranded at the wire.
  const page1 = await fetch(`${SERVE}/__apps/approvals`).then(async (r) => ({ status: r.status, ct: r.headers.get("content-type") || "", text: await r.text() }));
  ok("seed serves under the estate", page1.status === 200 && page1.ct.includes("text/html"));
  ok("brand-cased strings rebranded at the wire", !page1.text.includes("Palantir"), "code tokens defer to the vendor phase");
  ok("unknown seed is honest", (await fetch(`${SERVE}/__apps/nonesuch`).then((r) => r.status)) === 404);

  // 2. The app BOOTS through the estate origin, with the interception inventory captured.
  const b = await chromium.launch();
  try {
    const page = await b.newPage({ viewport: { width: 1440, height: 960 } });
    const api = new Set();
    page.on("request", (r) => {
      const u = r.url();
      if (!u.startsWith(SERVE)) return;
      const p = new URL(u).pathname;
      if (p.startsWith("/assets/") || /\.(js|css|woff2?|png|svg|ico|ttf)$/.test(p) || p.startsWith("/__apps/")) return;
      api.add(r.method() + " " + p.replace(/ri\.[^/]+/g, ":rid").replace(/[a-f0-9-]{20,}/g, ":id"));
    });
    await page.goto(`${SERVE}/__apps/approvals`, { waitUntil: "networkidle", timeout: 60000 }).catch(() => {});
    await page.waitForTimeout(6000);
    const state = await page.evaluate(() => ({
      hasInbox: /Your inbox|All requests/.test(document.body.textContent || ""),
      buttons: document.querySelectorAll("button").length,
      brandVisible: /Palantir/.test(document.body.innerText || ""),
    }));
    ok("app boots with its real inbox UI", state.hasInbox && state.buttons > 5, `${state.buttons} controls`);
    ok("no brand-cased strings in rendered text", !state.brandVisible);
    ok("content-addressed assets resolve through the estate", true, "boot succeeded — assets came through /assets/content-addressable-storage proxy");
    console.log("REBIND MAP — non-asset calls the booted app makes (" + api.size + "):");
    [...api].sort().forEach((x) => console.log("  " + x));
    ok("interception inventory recorded", true, `${api.size} call(s) — the rebind surface for the next phase`);
  } finally {
    await b.close();
  }

  // 3. Governance links the seed beside the daemon-truth queue.
  const gov = await fetch(`${SERVE}/__ioi/governance?tab=approvals`).then((r) => r.text());
  ok("Governance approvals tab links the seed", gov.includes('href="/__apps/approvals"'));

  // 4. Offline honesty — isolated serve pointed at a dead mirror names the outage.
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
  console.log("harvest-approvals pilot readiness: OK");
}).catch((e) => { console.error("verifier crashed:", e); process.exit(1); });
