#!/usr/bin/env node
// Behavioral contract test — source-owned shell + Home cockpit (cut 4 gate).
// Asserts rail nav, sessions from the native threads plane (/v1/threads, no upstream bridge),
// the intent composer, and Recent Sessions. Deterministic via route mocking.
// Requires the vite dev server on :1420. Run: node apps/hypervisor/tests/home.contract.mjs
import { chromium } from "playwright";

const BASE = process.env.APP_URL || "http://127.0.0.1:1420";
const fails = [];
const ok = (n) => console.log(`  ✓ ${n}`);
const bad = (n, d) => { fails.push(n); console.error(`  ✗ ${n}${d ? " — " + d : ""}`); };

const THREADS = {
  threads: [
    { thread_id: "t1", title: "Port the Projects surface", status: "active", updated_at: new Date(Date.now() - 3600e3).toISOString() },
    { thread_id: "t2", title: ".", status: "stopped", updated_at: new Date(Date.now() - 86400e3).toISOString() },
  ],
};

const browser = await chromium.launch();
const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 }, colorScheme: "dark" });
const page = await ctx.newPage();
const seen = [];
await page.route("**/v1/**", (route) => {
  const u = route.request().url();
  seen.push(u.replace(/^https?:\/\/[^/]+/, ""));
  if (u.includes("/v1/threads")) return route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(THREADS) });
  return route.fulfill({ status: 200, contentType: "application/json", body: "{}" });
});
await page.route("**/api/**", (route) => { seen.push(route.request().url().replace(/^https?:\/\/[^/]+/, "")); route.fulfill({ status: 404, body: "" }); });

await page.goto(`${BASE}/`, { waitUntil: "networkidle" });
await page.waitForTimeout(600);

const m = await page.evaluate(() => ({
  rail: !!document.querySelector("[data-testid=app-rail]"),
  nav: [...document.querySelectorAll("[data-testid=rail-nav] a")].map((a) => a.textContent?.trim()),
  railSessions: document.querySelectorAll("[data-testid=rail-session]").length,
  title: document.querySelector(".hm-title")?.textContent,
  composer: !!document.querySelector("[data-testid=composer]"),
  send: !!document.querySelector("[data-testid=composer-send]"),
  recent: document.querySelectorAll("[data-testid=recent-row]").length,
  recentTitle: document.querySelector("[data-testid=recent-row] .hm-recenttitle")?.textContent,
  untitledMapped: [...document.querySelectorAll("[data-testid=recent-row] .hm-recenttitle")].some((e) => e.textContent === "Untitled session"),
}));

m.rail ? ok("rail present") : bad("rail present");
["Home", "Projects", "Automations", "Applications", "Connections"].every((l) => m.nav.includes(l))
  ? ok("rail nav: Home/Projects/Automations/Applications/Connections")
  : bad("rail nav", m.nav.join(","));
m.railSessions === 2 ? ok("rail sessions from /v1/threads (2)") : bad("rail sessions", `got ${m.railSessions}`);
m.title === "What do you want to get done today?" ? ok("cockpit title") : bad("cockpit title", m.title);
m.composer && m.send ? ok("intent composer + send") : bad("composer");
m.recent === 2 ? ok("recent sessions (2)") : bad("recent sessions", `got ${m.recent}`);
m.recentTitle === "Port the Projects surface" ? ok("real thread title rendered") : bad("thread title", m.recentTitle);
m.untitledMapped ? ok('"." title mapped to "Untitled session"') : bad("untitled mapping");

const native = seen.some((s) => s.includes("/v1/threads"));
const bridged = seen.some((s) => /\/api\/[a-z][a-z0-9.]*\.v\d+\//i.test(s));
native ? ok("uses native /v1/threads") : bad("native threads plane");
!bridged ? ok("no upstream-wire bridge") : bad("no upstream-wire bridge");

await browser.close();
if (fails.length) { console.error(`\nhome/shell contract FAILED: ${fails.length}`); process.exit(1); }
console.log("\nhome/shell contract PASSED.");
