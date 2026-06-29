#!/usr/bin/env node
// Behavioral contract test — source-owned Projects surface (cut 4 gate).
// Asserts the native daemon RPC contract (protocol-native: no upstream wire), DOM landmarks from
// mocked data, search filtering, and empty/error states. Deterministic via route mocking.
//
// Requires the vite dev server on :1420 (npm run dev --workspace=@ioi/hypervisor-app)
// with the /projects route wired to ProjectsView.
// Run: node apps/hypervisor/tests/projects.contract.mjs
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
const SAMPLE = {
  "/hypervisor/projects": json({ projects: [
    { project_id: "project:repo-archive", name: "Repo Archive", repository_url: "https://github.com/teamioitest/repoarchive.git", repository_branch: "main", environment: "No environment yet", environment_class_refs: ["local-workspace-v0"], prebuilds_enabled: true, restore_state: "active", created_at: new Date(Date.now() - 3600e3).toISOString() },
    { project_id: "project:demo", name: "Demo Service", repository_url: "https://github.com/teamioitest/demo.git", repository_branch: "develop", environment: "No environment yet", environment_class_refs: [], prebuilds_enabled: false, restore_state: "active", created_at: new Date(Date.now() - 86400e3).toISOString() },
    { project_id: "project:noname", name: "", repository_url: "https://github.com/teamioitest/archived.git", restore_state: "archived", created_at: new Date(Date.now() - 7 * 86400e3).toISOString() },
  ] }),
};

// --- Test A: native RPC contract + no upstream-wire bridge ---
await withPage(SAMPLE, async (page, seen) => {
  await page.goto(`${BASE}/projects`, { waitUntil: "networkidle" });
  await page.waitForTimeout(500);
  seen.some((s) => s.includes("/v1/hypervisor/projects"))
    ? ok("calls /v1/hypervisor/projects")
    : bad("calls /v1/hypervisor/projects", "not requested");
  // A bridge call is any /api/<package>.vN/ request (the upstream Connect-RPC namespace).
  const bridged = seen.filter((s) => /\/api\/[a-z][a-z0-9.]*\.v\d+\//i.test(s));
  bridged.length === 0 ? ok("no upstream-wire bridge (no /api/<pkg>.vN/ calls)") : bad("no upstream-wire bridge", bridged.join(","));
});

// --- Test B: data → DOM landmarks (page, header, search, cards, derived fields) ---
await withPage(SAMPLE, async (page) => {
  await page.goto(`${BASE}/projects`, { waitUntil: "networkidle" });
  await page.waitForTimeout(500);
  const m = await page.evaluate(() => ({
    page: !!document.querySelector("[data-testid=projects-page]"),
    h1: document.querySelector(".pj-h1")?.textContent,
    search: !!document.querySelector("[data-testid=projects-search]"),
    newBtn: !!document.querySelector("[data-testid=create-project-button]"),
    cards: document.querySelectorAll("[data-testid=project-card]").length,
    firstName: document.querySelector("[data-testid=project-card] .pj-card-name")?.textContent,
    repoLabels: [...document.querySelectorAll(".pj-card-repo")].map((e) => e.textContent),
    prebuilds: document.body.innerText.includes("prebuilds"),
    archived: [...document.querySelectorAll(".pj-pill")].some((e) => e.textContent === "archived"),
    nameFallback: [...document.querySelectorAll(".pj-card-name")].some((e) => e.textContent === "teamioitest/archived"),
  }));
  m.page ? ok("renders projects-page landmark") : bad("projects-page landmark");
  m.h1 === "Projects" ? ok("page title 'Projects'") : bad("page title", m.h1);
  m.search ? ok("search box present") : bad("search box");
  m.newBtn ? ok("New project button present") : bad("New project button");
  m.cards === 3 ? ok("renders 3 project cards") : bad("project cards", `got ${m.cards}`);
  m.firstName === "Repo Archive" ? ok("newest-first ordering + name rendered") : bad("first card name", m.firstName);
  m.repoLabels.includes("teamioitest/repoarchive") ? ok("repo label derived (owner/repo)") : bad("repo label", m.repoLabels.join(","));
  m.prebuilds ? ok("prebuilds flag rendered") : bad("prebuilds flag");
  m.archived ? ok("archived pill rendered") : bad("archived pill");
  m.nameFallback ? ok("blank name falls back to repo label") : bad("name fallback");
});

// --- Test C: search filtering ---
await withPage(SAMPLE, async (page) => {
  await page.goto(`${BASE}/projects`, { waitUntil: "networkidle" });
  await page.waitForTimeout(400);
  await page.fill("[data-testid=projects-search]", "demo");
  await page.waitForTimeout(200);
  const m = await page.evaluate(() => ({
    cards: document.querySelectorAll("[data-testid=project-card]").length,
    name: document.querySelector("[data-testid=project-card] .pj-card-name")?.textContent,
  }));
  m.cards === 1 && m.name === "Demo Service" ? ok("search filters to matching project") : bad("search filter", `cards=${m.cards} name=${m.name}`);
  await page.fill("[data-testid=projects-search]", "zzz-no-match");
  await page.waitForTimeout(200);
  (await page.locator("[data-testid=projects-no-matches]").count()) ? ok("no-matches state") : bad("no-matches state");
});

// --- Test D: empty + error states ---
await withPage({ "/hypervisor/projects": json({ projects: [] }) }, async (page) => {
  await page.goto(`${BASE}/projects`, { waitUntil: "networkidle" });
  await page.waitForTimeout(400);
  const m = await page.evaluate(() => ({
    empty: !!document.querySelector("[data-testid=projects-empty]"),
    title: document.querySelector(".pj-empty-title")?.textContent,
  }));
  m.empty && m.title === "No projects" ? ok("empty state ('No projects')") : bad("empty state", m.title);
});
await withPage({ "/hypervisor/projects": { status: 500, body: "boom" } }, async (page) => {
  await page.goto(`${BASE}/projects`, { waitUntil: "networkidle" });
  await page.waitForTimeout(400);
  // listProjects swallows the failure and yields an empty list (graceful) → empty state, no crash.
  (await page.locator("[data-testid=projects-empty], [data-testid=projects-error]").count())
    ? ok("daemon-down handled gracefully")
    : bad("daemon-down handling");
});

await browser.close();
if (fails.length) { console.error(`\nprojects contract FAILED: ${fails.length} assertion(s)`); process.exit(1); }
console.log("\nprojects contract PASSED.");
