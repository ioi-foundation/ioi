#!/usr/bin/env node
// Behavioral contract test — source-owned Project detail surface (/projects/:id).
// Asserts the native daemon RPC contract (protocol-native: no upstream wire), DOM landmarks from
// mocked project + environment data, the project→environment binding, and missing/error states.
// Deterministic via route mocking.
//
// Requires the vite dev server on :1420 with the /projects/:id route wired to ProjectDetailView.
// Run: node apps/hypervisor/tests/project-detail.contract.mjs
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
const PROJECTS = json({ projects: [
  { project_id: "project:demo", name: "Demo Service", repository_url: "https://github.com/teamioitest/demo.git", repository_branch: "develop", environment: "No environment yet", environment_class_refs: ["local-workspace-v0"], prebuilds_enabled: true, restore_state: "active", created_at: new Date(Date.now() - 3600e3).toISOString() },
] });
const ENVIRONMENTS = json({ environments: [
  { id: "env_running", created_at: new Date(Date.now() - 600e3).toISOString(), spec: { project_id: "demo", environment_class_id: "local-workspace-v0" }, status: { phase: "running" } },
  { id: "env_stopped", created_at: new Date(Date.now() - 7200e3).toISOString(), spec: { project_id: "demo", environment_class_id: "local-workspace-v0" }, status: { phase: "stopped" } },
  { id: "env_other", created_at: new Date().toISOString(), spec: { project_id: "someone-else" }, status: { phase: "running" } },
  { id: "env_deleted", created_at: new Date().toISOString(), spec: { project_id: "demo" }, status: { phase: "deleted", deleted: true } },
] });
const SAMPLE = { "/hypervisor/projects": PROJECTS, "/hypervisor/environments": ENVIRONMENTS };
const ID = encodeURIComponent("project:demo");

// --- Test A: native RPC contract + no upstream-wire bridge ---
await withPage(SAMPLE, async (page, seen) => {
  await page.goto(`${BASE}/projects/${ID}`, { waitUntil: "networkidle" });
  await page.waitForTimeout(500);
  seen.some((s) => s.includes("/v1/hypervisor/projects")) ? ok("calls /v1/hypervisor/projects") : bad("calls /v1/hypervisor/projects", "not requested");
  seen.some((s) => s.includes("/v1/hypervisor/environments")) ? ok("calls /v1/hypervisor/environments") : bad("calls /v1/hypervisor/environments", "not requested");
  const bridged = seen.filter((s) => /\/api\/[a-z][a-z0-9.]*\.v\d+\//i.test(s));
  bridged.length === 0 ? ok("no upstream-wire bridge (no /api/<pkg>.vN/ calls)") : bad("no upstream-wire bridge", bridged.join(","));
});

// --- Test B: data → DOM landmarks (header, facts, env binding by project_id slug) ---
await withPage(SAMPLE, async (page) => {
  await page.goto(`${BASE}/projects/${ID}`, { waitUntil: "networkidle" });
  await page.waitForTimeout(500);
  const m = await page.evaluate(() => ({
    pageL: !!document.querySelector("[data-testid=project-detail-page]"),
    back: !!document.querySelector("[data-testid=project-detail-back]"),
    name: document.querySelector("[data-testid=project-detail-name]")?.textContent?.trim(),
    repo: document.querySelector("[data-testid=project-detail-repo]")?.textContent,
    facts: !!document.querySelector("[data-testid=project-detail-facts]"),
    branch: document.body.innerText.includes("develop"),
    prebuilds: document.body.innerText.includes("Enabled"),
    envs: document.querySelectorAll("[data-testid=project-environment]").length,
    running: document.querySelectorAll(".pjd-env-dot.is-running").length,
  }));
  m.pageL ? ok("renders project-detail-page landmark") : bad("project-detail-page landmark");
  m.back ? ok("back link present") : bad("back link");
  m.name?.startsWith("Demo Service") ? ok("project name rendered") : bad("project name", m.name);
  m.repo?.includes("teamioitest/demo") ? ok("repo label rendered") : bad("repo label", m.repo);
  m.facts ? ok("facts block present") : bad("facts block");
  m.branch ? ok("branch fact rendered") : bad("branch fact");
  m.prebuilds ? ok("prebuilds fact rendered") : bad("prebuilds fact");
  m.envs === 2 ? ok("binds 2 env rows by project slug (excludes other/deleted)") : bad("env binding", `got ${m.envs}`);
  m.running === 1 ? ok("1 running env dot") : bad("running dot", `got ${m.running}`);
});

// --- Test C: environments-empty state (project with no envs) ---
await withPage({ "/hypervisor/projects": PROJECTS, "/hypervisor/environments": json({ environments: [] }) }, async (page) => {
  await page.goto(`${BASE}/projects/${ID}`, { waitUntil: "networkidle" });
  await page.waitForTimeout(400);
  (await page.locator("[data-testid=project-detail-environments-empty]").count()) ? ok("environments-empty state") : bad("environments-empty state");
});

// --- Test D: missing project + daemon-down ---
await withPage({ "/hypervisor/projects": json({ projects: [] }), "/hypervisor/environments": json({ environments: [] }) }, async (page) => {
  await page.goto(`${BASE}/projects/${encodeURIComponent("project:ghost")}`, { waitUntil: "networkidle" });
  await page.waitForTimeout(400);
  (await page.locator("[data-testid=project-detail-missing]").count()) ? ok("missing-project state") : bad("missing-project state");
});
await withPage({ "/hypervisor/projects": { status: 500, body: "boom" }, "/hypervisor/environments": { status: 500, body: "boom" } }, async (page) => {
  await page.goto(`${BASE}/projects/${ID}`, { waitUntil: "networkidle" });
  await page.waitForTimeout(400);
  // getProject swallows the failure → empty list → missing state (graceful, no crash).
  (await page.locator("[data-testid=project-detail-missing], [data-testid=project-detail-error]").count())
    ? ok("daemon-down handled gracefully")
    : bad("daemon-down handling");
});

await browser.close();
if (fails.length) { console.error(`\nproject-detail contract FAILED: ${fails.length} assertion(s)`); process.exit(1); }
console.log("\nproject-detail contract PASSED.");
