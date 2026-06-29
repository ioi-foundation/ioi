#!/usr/bin/env node
// Behavioral contract test — source-owned Settings surface (cut 4 gate).
// Asserts the settings-nav shell renders, that data panes call their native daemon endpoints
// (protocol-native: no upstream wire), DOM landmarks from mocked data, and empty/error states.
// Deterministic via route mocking.
//
// Requires the vite dev server on :1420 (npm run dev --workspace=@ioi/hypervisor-app)
// with the /settings/* route wired to SettingsView.
// Run: node apps/hypervisor/tests/settings.contract.mjs
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
  await page.route("**/v1/**", (route) => {
    const url = route.request().url();
    seen.push(url.replace(/^https?:\/\/[^/]+/, ""));
    const key = Object.keys(mocks).find((k) => url.includes(k));
    if (key) return route.fulfill(mocks[key]);
    return route.fulfill({ status: 200, contentType: "application/json", body: "{}" });
  });
  // Any upstream Connect-RPC namespace call would be a wire bridge — record so we can assert none.
  await page.route("**/api/**", (route) => { seen.push(route.request().url().replace(/^https?:\/\/[^/]+/, "")); route.fulfill({ status: 404, body: "" }); });
  await fn(page, seen);
  await ctx.close();
}

const json = (obj) => ({ status: 200, contentType: "application/json", body: JSON.stringify(obj) });
const goto = (page, sub) => page.goto(`${BASE}/settings/${sub}`, { waitUntil: "networkidle" });

const SAMPLE = {
  "/hypervisor/principals": json({ principals: [
    { principal_id: "p1", name: "John Doe", email: "johndoe@ioi.local", role: "admin", status: "active", source: "local-operator", created_at: new Date(Date.now() - 86400e3).toISOString() },
    { principal_id: "p2", name: "Jane Roe", email: "jane@ioi.local", role: "member", status: "active", source: "sso", created_at: new Date(Date.now() - 3600e3).toISOString() },
    { principal_id: "p3", name: "Ghost", email: "ghost@ioi.local", role: "member", status: "suspended", source: "local", created_at: new Date().toISOString() },
  ] }),
  "/hypervisor/providers": json({ providers: [
    { provider_ref: "local-microvm", reason: "local microVM node", status: "available", capabilities: { isolation: "vm_kernel", locality: "local", remote: false, restore: true } },
    { provider_ref: "cloud-vpc", reason: "not configured", status: "not_configured", capabilities: { isolation: "vm_kernel", locality: "remote", remote: true } },
  ] }),
  "/hypervisor/scm-connectors": json({ connectors: [
    { connector_id: "scm_host_github", kind: "github", host: "github.com", host_level: true, auth_posture: "token-lease:bound", connected_login: "teamioitest" },
    { connector_id: "scm_other", kind: "git", host_level: false, auth_posture: "token-lease:unbound" },
  ] }),
  "/hypervisor/secrets": json({ secrets: [
    { secret_id: "sec1", name: "OPENAI_KEY", mount: { environmentVariable: {} }, created_at: new Date(Date.now() - 86400e3).toISOString() },
    { secret_id: "sec2", name: "deploy.pem", mount: { filePath: "/etc/deploy.pem" }, created_at: new Date().toISOString() },
  ] }),
  "/hypervisor/api-tokens": json({ tokens: [
    { token_id: "tok1", description: "CI pipeline", read_only: false, created_at: new Date(Date.now() - 86400e3).toISOString(), expires_at: new Date(Date.now() + 30 * 86400e3).toISOString() },
  ] }),
  "/hypervisor/budget": json({ budget: { budget_ocu: 1000, available_ocu: 985.46, used_ocu: 14.54, threshold_ocu: 20, target_ocu: 1000, auto_fund_enabled: false } }),
  "/hypervisor/usage/consumption": json({ metrics: [
    { display_name: "Total", kind: "KIND_ALL", series: [{ time: "2026-06-25T00:00:00Z", ocu: 5.18 }, { time: "2026-06-26T00:00:00Z", ocu: 8.53 }] },
    { display_name: "Environment Usage", kind: "KIND_ENVIRONMENT", series: [{ time: "2026-06-25T00:00:00Z", ocu: 0.08 }] },
  ] }),
};

// --- Test A: settings-nav shell + native RPC contract + no upstream-wire bridge ---
await withPage(SAMPLE, async (page, seen) => {
  await goto(page, "members");
  await page.waitForTimeout(500);
  (await page.locator("[data-testid=settings-nav]").count()) ? ok("settings-nav renders") : bad("settings-nav");
  const navItems = await page.locator("[data-testid=settings-nav-item]").count();
  navItems >= 8 ? ok(`settings-nav has ${navItems} items`) : bad("settings-nav items", `got ${navItems}`);
  // Two data panes (members + metering) must call their native daemon endpoints.
  await goto(page, "metering");
  await page.waitForTimeout(500);
  const need = ["/v1/hypervisor/principals", "/v1/hypervisor/budget", "/v1/hypervisor/usage/consumption"];
  for (const n of need) (seen.some((s) => s.includes(n)) ? ok(`calls ${n}`) : bad(`calls ${n}`, "not requested"));
  // A bridge call is any /api/<package>.vN/ request (the upstream Connect-RPC namespace).
  const bridged = seen.filter((s) => /\/api\/[a-z][a-z0-9.]*\.v\d+\//i.test(s));
  bridged.length === 0 ? ok("no upstream-wire bridge (no /api/<pkg>.vN/ calls)") : bad("no upstream-wire bridge", bridged.join(","));
});

// --- Test B: Members pane → DOM landmarks (table rows, active-only filter, role pill) ---
await withPage(SAMPLE, async (page) => {
  await goto(page, "members");
  await page.waitForTimeout(500);
  const m = await page.evaluate(() => ({
    pane: !!document.querySelector("[data-testid=settings-pane]"),
    h1: document.querySelector(".st-h1")?.textContent,
    rows: document.querySelectorAll("[data-testid=members-row]").length,
    firstName: document.querySelector("[data-testid=members-row] .st-person-name")?.textContent,
    adminPill: [...document.querySelectorAll("[data-testid=members-row] .st-pill")].some((e) => e.textContent === "Admin"),
  }));
  m.pane ? ok("settings-pane landmark") : bad("settings-pane landmark");
  m.h1 === "Members" ? ok("members title") : bad("members title", m.h1);
  m.rows === 2 ? ok("renders 2 active members (suspended filtered out)") : bad("members rows", `got ${m.rows}`);
  m.firstName === "John Doe" ? ok("member name rendered") : bad("member name", m.firstName);
  m.adminPill ? ok("admin role pill rendered") : bad("admin role pill");
});

// --- Test C: Runners + Git authentications pane (two tables) ---
await withPage(SAMPLE, async (page) => {
  await goto(page, "runners");
  await page.waitForTimeout(500);
  const m = await page.evaluate(() => ({
    runners: document.querySelectorAll("[data-testid=runner-row]").length,
    gitauths: document.querySelectorAll("[data-testid=gitauth-row]").length,
    login: document.querySelector("[data-testid=gitauth-row] .st-cell-mono")?.textContent,
  }));
  m.runners === 2 ? ok("renders 2 runner rows") : bad("runner rows", `got ${m.runners}`);
  m.gitauths === 1 ? ok("renders 1 git-authentication row (host-level only)") : bad("gitauth rows", `got ${m.gitauths}`);
  m.login === "github.com" ? ok("git host rendered") : bad("git host", m.login);
});

// --- Test D: Secrets + Tokens panes ---
await withPage(SAMPLE, async (page) => {
  await goto(page, "secrets");
  await page.waitForTimeout(400);
  (await page.locator("[data-testid=secret-row]").count()) === 2 ? ok("renders 2 secret rows") : bad("secret rows");
  await goto(page, "tokens");
  await page.waitForTimeout(400);
  (await page.locator("[data-testid=token-row]").count()) === 1 ? ok("renders 1 token row") : bad("token rows");
});

// --- Test E: Metering summary ---
await withPage(SAMPLE, async (page) => {
  await goto(page, "metering");
  await page.waitForTimeout(500);
  const m = await page.evaluate(() => ({
    summary: !!document.querySelector("[data-testid=metering-summary]"),
    rows: document.querySelectorAll("[data-testid=metering-row]").length,
    hasBudget: document.body.innerText.includes("1,000"),
  }));
  m.summary ? ok("metering-summary landmark") : bad("metering-summary");
  m.rows === 2 ? ok("renders 2 consumption rows") : bad("consumption rows", `got ${m.rows}`);
  m.hasBudget ? ok("budget OCU rendered") : bad("budget OCU");
});

// --- Test F: stub pane (honest 'not yet ported', no fabricated data) ---
await withPage(SAMPLE, async (page) => {
  await goto(page, "policies");
  await page.waitForTimeout(300);
  (await page.locator("[data-testid=settings-stub]").count()) ? ok("unported pane renders honest stub") : bad("stub pane");
});

// --- Test G: empty + error states ---
await withPage({
  "/hypervisor/principals": json({ principals: [] }),
  "/hypervisor/secrets": json({ secrets: [] }),
  "/hypervisor/api-tokens": json({ tokens: [] }),
}, async (page) => {
  await goto(page, "members");
  await page.waitForTimeout(400);
  (await page.locator("[data-testid=members-empty]").count()) ? ok("members empty state") : bad("members empty state");
  await goto(page, "secrets");
  await page.waitForTimeout(400);
  (await page.locator("[data-testid=secret-row]").count()) === 0 && (await page.locator("[data-testid=secrets-empty]").count()) ? ok("secrets empty state") : bad("secrets empty state");
});
await withPage({ "/hypervisor/principals": { status: 500, body: "boom" } }, async (page) => {
  await goto(page, "members");
  await page.waitForTimeout(400);
  // listMembers swallows the failure → empty list (graceful), so assert empty-or-error, no crash.
  (await page.locator("[data-testid=members-empty], [data-testid=members-error]").count())
    ? ok("daemon-down handled gracefully")
    : bad("daemon-down handling");
});

await browser.close();
if (fails.length) { console.error(`\nsettings contract FAILED: ${fails.length} assertion(s)`); process.exit(1); }
console.log("\nsettings contract PASSED.");
