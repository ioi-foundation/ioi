#!/usr/bin/env node
// Behavioral contract test — source-owned Automations surface (cut 4 gate).
// Asserts route state, the native daemon RPC contract (protocol-native: no upstream wire),
// DOM landmarks, and empty/error states. Deterministic via route mocking.
//
// Requires the vite dev server on :1420 (npm run dev --workspace=@ioi/hypervisor-app).
// Run: node apps/hypervisor/tests/automations.contract.mjs
import { chromium } from "playwright";

const BASE = process.env.APP_URL || "http://127.0.0.1:1420";
const fails = [];
const ok = (name) => console.log(`  ✓ ${name}`);
const bad = (name, detail) => { fails.push(name); console.error(`  ✗ ${name}${detail ? " — " + detail : ""}`); };

const browser = await chromium.launch();

async function withPage(mocks, fn) {
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 }, colorScheme: "dark" });
  const page = await ctx.newPage();
  const seen = [];
  await page.route("**/v1/hypervisor/**", (route) => {
    const url = route.request().url();
    seen.push(url.replace(/^https?:\/\/[^/]+/, ""));
    const key = Object.keys(mocks).find((k) => url.includes(k));
    if (key) return route.fulfill(mocks[key]);
    return route.fulfill({ status: 200, contentType: "application/json", body: "{}" });
  });
  await page.route("**/api/**", (route) => { seen.push(route.request().url().replace(/^https?:\/\/[^/]+/, "")); route.fulfill({ status: 404, body: "" }); });
  await fn(page, seen);
  await ctx.close();
}

const json = (obj) => ({ status: 200, contentType: "application/json", body: JSON.stringify(obj) });
const SAMPLE = {
  "/automations": json({ ok: true, automations: [
    { automation_id: "auto_a", name: "demo-loop", project_id: "orchestration-verify", environment_class_id: "local-workspace-v0",
      trigger: { kind: "manual" }, steps: [{ kind: "agent" }, { kind: "command" }, { kind: "proposal" }],
      created_at: new Date(Date.now() - 3600e3).toISOString() },
    { automation_id: "auto_b", name: "nightly-report", project_id: "reporting", environment_class_id: "local-workspace-v0",
      trigger: { kind: "schedule", cron: "0 2 * * *" }, steps: [{ kind: "agent" }],
      created_at: new Date(Date.now() - 86400e3).toISOString() },
  ] }),
};

// --- Test A: native RPC contract + no upstream-wire bridge ---
await withPage(SAMPLE, async (page, seen) => {
  await page.goto(`${BASE}/automations`, { waitUntil: "networkidle" });
  await page.waitForTimeout(500);
  seen.some((s) => s.includes("/v1/hypervisor/automations"))
    ? ok("calls /v1/hypervisor/automations")
    : bad("calls /v1/hypervisor/automations", "not requested");
  // A bridge call is any /api/<package>.vN/ request (the upstream Connect-RPC namespace).
  const bridged = seen.filter((s) => /\/api\/[a-z][a-z0-9.]*\.v\d+\//i.test(s));
  bridged.length === 0 ? ok("no upstream-wire bridge (no /api/<pkg>.vN/ calls)") : bad("no upstream-wire bridge", bridged.join(","));
});

// --- Test B: data → DOM landmarks (header, New action, stat cards, rows, trigger pills) ---
await withPage(SAMPLE, async (page) => {
  await page.goto(`${BASE}/automations`, { waitUntil: "networkidle" });
  await page.waitForTimeout(500);
  const m = await page.evaluate(() => ({
    h1: document.querySelector(".au-h1")?.textContent,
    newAction: !!document.querySelector("[data-testid=automations-new]"),
    stats: document.querySelectorAll("[data-testid=automation-stat]").length,
    rows: document.querySelectorAll("[data-testid=automation-row]").length,
    runs: document.querySelectorAll("[data-testid=automation-run]").length,
    triggers: [...document.querySelectorAll(".au-trigger")].map((e) => e.textContent),
    firstName: document.querySelector("[data-testid=automation-row] .au-rowname")?.textContent?.trim(),
    totalValue: document.querySelector("[data-testid=automation-stat].is-accent .au-statvalue")?.textContent,
  }));
  m.h1 === "Automations" ? ok("page title 'Automations'") : bad("page title", m.h1);
  m.newAction ? ok("New action present") : bad("New action");
  m.stats === 3 ? ok("renders 3 stat cards") : bad("stat cards", `got ${m.stats}`);
  m.rows === 2 ? ok("renders 2 automation rows") : bad("automation rows", `got ${m.rows}`);
  m.runs === 2 ? ok("each row has a Run action") : bad("run actions", `got ${m.runs}`);
  m.triggers.some((t) => t === "Manual") && m.triggers.some((t) => /Schedule/.test(t || ""))
    ? ok("trigger pills (Manual + Schedule) rendered")
    : bad("trigger pills", m.triggers.join(","));
  // sorted newest-first → nightly (older) after demo-loop (newer)
  m.firstName?.startsWith("demo-loop") ? ok("rows sorted newest-first") : bad("row sort", m.firstName);
  m.totalValue === "2" ? ok("total stat reflects count (2)") : bad("total stat", m.totalValue);
});

// --- Test C: empty state ---
await withPage({ "/automations": json({ ok: true, automations: [] }) }, async (page) => {
  await page.goto(`${BASE}/automations`, { waitUntil: "networkidle" });
  await page.waitForTimeout(400);
  const m = await page.evaluate(() => ({
    empty: !!document.querySelector("[data-testid=automations-empty]"),
    rows: document.querySelectorAll("[data-testid=automation-row]").length,
    stats: document.querySelectorAll("[data-testid=automation-stat]").length,
  }));
  m.empty && m.rows === 0 ? ok("empty state (no rows)") : bad("empty state", `empty=${m.empty} rows=${m.rows}`);
  m.stats === 3 ? ok("stat cards still render when empty (all zero)") : bad("empty stats", `got ${m.stats}`);
});

// --- Test D: error / daemon-down ---
await withPage({ "/automations": { status: 500, body: "boom" } }, async (page) => {
  await page.goto(`${BASE}/automations`, { waitUntil: "networkidle" });
  await page.waitForTimeout(400);
  // fetchAutomations swallows the failure → graceful empty (no crash).
  (await page.locator("[data-testid=automations-empty], [data-testid=automations-error]").count())
    ? ok("daemon-down handled gracefully")
    : bad("daemon-down handling");
});

await browser.close();
if (fails.length) { console.error(`\nautomations contract FAILED: ${fails.length} assertion(s)`); process.exit(1); }
console.log("\nautomations contract PASSED.");
