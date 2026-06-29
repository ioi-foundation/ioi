#!/usr/bin/env node
// Behavioral contract test — source-owned Connections surface (cut 4 gate).
// Asserts route state, the native daemon RPC contract (protocol-native: no upstream wire),
// DOM landmarks, and empty/error states. Deterministic via route mocking.
//
// Requires the vite dev server on :1420 (npm run dev --workspace=@ioi/hypervisor-app).
// Run: node apps/hypervisor/tests/connections.contract.mjs
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
  "/connectors": json({ connectors: [
    { connector_id: "c_mcp_ok", name: "Notion", service: "notion", kind: "mcp", base_url: "https://mcp.notion.com/mcp", auth_posture: "token-lease:bound", auth_profile: { type: "oauth_authcode_pkce", discovered: true }, org_policy: { risk_posture: "standard" } },
    { connector_id: "c_mcp_need", name: "Linear", service: "linear", kind: "mcp", base_url: "https://mcp.linear.app/mcp", auth_posture: "unbound", auth_profile: { type: "oauth_authcode_pkce", discovered: true }, org_policy: { risk_posture: "standard" } },
  ] }),
  "/scm-connectors": json({ connectors: [
    { name: "github:@teamioitest", kind: "github", host: "github.com", auth_posture: "token-lease:bound", connected_login: "teamioitest" },
  ] }),
  "/capability-leases": json({ leases: [{ backing_provider: "c_mcp_ok", resource_refs: "x" }] }),
};

// --- Test A: native RPC contract + no upstream-wire bridge ---
await withPage(SAMPLE, async (page, seen) => {
  await page.goto(`${BASE}/connections`, { waitUntil: "networkidle" });
  await page.waitForTimeout(500);
  const need = ["/v1/hypervisor/connectors", "/v1/hypervisor/scm-connectors", "/v1/hypervisor/capability-leases"];
  for (const n of need) (seen.some((s) => s.includes(n)) ? ok(`calls ${n}`) : bad(`calls ${n}`, "not requested"));
  // A bridge call is any /api/<package>.vN/ request (the upstream Connect-RPC namespace).
  const bridged = seen.filter((s) => /\/api\/[a-z][a-z0-9.]*\.v\d+\//i.test(s));
  bridged.length === 0 ? ok("no upstream-wire bridge (no /api/<pkg>.vN/ calls)") : bad("no upstream-wire bridge", bridged.join(","));
});

// --- Test B: data → DOM landmarks (categories, cards, status pills, lease count) ---
await withPage(SAMPLE, async (page) => {
  await page.goto(`${BASE}/connections`, { waitUntil: "networkidle" });
  await page.waitForTimeout(500);
  const m = await page.evaluate(() => ({
    groups: document.querySelectorAll("[data-testid=connection-group]").length,
    cards: document.querySelectorAll("[data-testid=connection-card]").length,
    connected: document.querySelectorAll(".cx-pill.cx-ok").length,
    needsAuth: document.querySelectorAll(".cx-pill.cx-warn").length,
    leaseText: document.body.innerText.includes("1 lease issued"),
    mcpHeading: [...document.querySelectorAll(".cx-h2")].some((h) => h.textContent === "MCP servers"),
    scmHeading: [...document.querySelectorAll(".cx-h2")].some((h) => h.textContent === "Code / SCM"),
  }));
  m.groups === 2 ? ok("renders 2 category groups (MCP + SCM)") : bad("category groups", `got ${m.groups}`);
  m.cards === 3 ? ok("renders 3 connector cards") : bad("cards", `got ${m.cards}`);
  m.connected === 2 ? ok("2 connected pills") : bad("connected pills", `got ${m.connected}`);
  m.needsAuth === 1 ? ok("1 needs-auth pill") : bad("needs-auth pill", `got ${m.needsAuth}`);
  m.leaseText ? ok("lease count rendered") : bad("lease count", "missing '1 lease issued'");
  m.mcpHeading && m.scmHeading ? ok("category headings correct") : bad("category headings");
});

// --- Test C: empty + error states ---
await withPage({ "/connectors": json({ connectors: [] }), "/scm-connectors": json({ connectors: [] }), "/capability-leases": json({ leases: [] }) }, async (page) => {
  await page.goto(`${BASE}/connections`, { waitUntil: "networkidle" });
  await page.waitForTimeout(400);
  (await page.locator("[data-testid=connections-empty]").count()) ? ok("empty state") : bad("empty state");
});
await withPage({ "/connectors": { status: 500, body: "boom" }, "/scm-connectors": { status: 500, body: "boom" }, "/capability-leases": { status: 500, body: "boom" } }, async (page) => {
  await page.goto(`${BASE}/connections`, { waitUntil: "networkidle" });
  await page.waitForTimeout(400);
  // all three fail → fetchConnections swallows per-call and yields empty (graceful), so assert no crash + empty
  (await page.locator("[data-testid=connections-empty], [data-testid=connections-error]").count()) ? ok("daemon-down handled gracefully") : bad("daemon-down handling");
});

await browser.close();
if (fails.length) { console.error(`\nconnections contract FAILED: ${fails.length} assertion(s)`); process.exit(1); }
console.log("\nconnections contract PASSED.");
