#!/usr/bin/env node
// Behavioral contract test — source-owned Applications surface (cut 4 gate).
// Asserts route state, the favorites empty state, the static catalog (cards/categories/search),
// favoriting (catalog → favorites strip via localStorage), and NO upstream-wire bridge.
//
// The Hypervisor daemon owns no applications/favorites plane yet, so this surface renders an
// honest empty favorites state + a static IOI-owned catalog. The contract therefore asserts the
// catalog/empty anatomy and proves the surface makes no upstream Connect-RPC namespace call.
//
// Requires the vite dev server on :1420 (npm run dev --workspace=@ioi/hypervisor-app).
// Run: node apps/hypervisor/tests/applications.contract.mjs
import { chromium } from "playwright";

const BASE = process.env.APP_URL || "http://127.0.0.1:1420";
const fails = [];
const ok = (name) => console.log(`  ✓ ${name}`);
const bad = (name, detail) => { fails.push(name); console.error(`  ✗ ${name}${detail ? " — " + detail : ""}`); };

const browser = await chromium.launch();

async function withPage(fn) {
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 }, colorScheme: "dark" });
  const page = await ctx.newPage();
  const seen = [];
  // Record every backend-shaped request so we can prove no upstream-wire bridge is used.
  await page.route("**/v1/**", (route) => {
    seen.push(route.request().url().replace(/^https?:\/\/[^/]+/, ""));
    route.fulfill({ status: 200, contentType: "application/json", body: "{}" });
  });
  await page.route("**/api/**", (route) => {
    seen.push(route.request().url().replace(/^https?:\/\/[^/]+/, ""));
    route.fulfill({ status: 404, body: "" });
  });
  await fn(page, seen);
  await ctx.close();
}

// --- Test A: route renders — empty favorites + static catalog, no upstream-wire bridge ---
await withPage(async (page, seen) => {
  await page.goto(`${BASE}/applications`, { waitUntil: "networkidle" });
  await page.waitForTimeout(500);
  const m = await page.evaluate(() => ({
    heading: document.querySelector(".ap-h1")?.textContent,
    favSection: !!document.querySelector("[data-testid=applications-favorites]"),
    empty: !!document.querySelector("[data-testid=applications-empty]"),
    emptyText: document.querySelector("[data-testid=applications-empty]")?.textContent?.trim(),
    catalog: !!document.querySelector("[data-testid=applications-catalog]"),
    cards: document.querySelectorAll("[data-testid=app-card]").length,
    categories: document.querySelectorAll("[data-testid=applications-category]").length,
    detail: !!document.querySelector("[data-testid=applications-detail]"),
  }));
  m.heading === "Applications" ? ok("route renders (Applications heading)") : bad("heading", m.heading);
  m.favSection ? ok("favorites section present") : bad("favorites section");
  m.empty ? ok("empty favorites state shown by default") : bad("empty favorites state");
  m.emptyText === "Your favorite apps will appear here" ? ok("empty-state copy") : bad("empty-state copy", m.emptyText);
  m.catalog ? ok("catalog browser present") : bad("catalog browser");
  m.cards >= 50 ? ok(`static catalog renders app cards (${m.cards})`) : bad("app cards", `got ${m.cards}`);
  m.categories >= 9 ? ok(`category rail (${m.categories} incl. All apps)`) : bad("category rail", `got ${m.categories}`);
  m.detail ? ok("detail card present") : bad("detail card");

  // A bridge call is any /api/<package>.vN/ request (the upstream Connect-RPC namespace).
  const bridged = seen.filter((s) => /\/api\/[a-z][a-z0-9.]*\.v\d+\//i.test(s));
  bridged.length === 0 ? ok("no upstream-wire bridge (no /api/<pkg>.vN/ calls)") : bad("no upstream-wire bridge", bridged.join(","));
});

// --- Test B: category filter + search narrow the catalog ---
await withPage(async (page) => {
  await page.goto(`${BASE}/applications`, { waitUntil: "networkidle" });
  await page.waitForTimeout(400);
  const all = await page.locator("[data-testid=app-card]").count();
  // Click a non-"All apps" category and confirm the visible set shrinks.
  await page.locator("[data-testid=applications-category]").nth(1).click();
  await page.waitForTimeout(150);
  const filtered = await page.locator("[data-testid=app-card]").count();
  filtered > 0 && filtered < all ? ok(`category filter narrows (${all} → ${filtered})`) : bad("category filter", `${all} → ${filtered}`);
  // Search.
  await page.locator("[data-testid=applications-category]").first().click(); // back to All apps
  await page.locator("[data-testid=applications-search]").fill("ontology");
  await page.waitForTimeout(150);
  const searched = await page.locator("[data-testid=app-card]").count();
  searched > 0 && searched < all ? ok(`search narrows (${searched} hits for "ontology")`) : bad("search", `got ${searched}`);
});

// --- Test C: favoriting moves an app into the favorites strip ---
await withPage(async (page) => {
  await page.goto(`${BASE}/applications`, { waitUntil: "networkidle" });
  await page.waitForTimeout(400);
  (await page.locator("[data-testid=applications-empty]").count()) ? ok("starts with empty favorites") : bad("empty favorites at start");
  await page.locator("[data-testid=favorite-toggle]").first().click();
  await page.waitForTimeout(150);
  const favCards = await page.locator("[data-testid=applications-favorites] [data-testid=app-card]").count();
  favCards === 1 ? ok("favoriting adds a card to the favorites strip") : bad("favorite add", `got ${favCards}`);
  const stillEmpty = await page.locator("[data-testid=applications-empty]").count();
  stillEmpty === 0 ? ok("empty state cleared after favoriting") : bad("empty state should clear");
});

await browser.close();
if (fails.length) { console.error(`\napplications contract FAILED: ${fails.length} assertion(s)`); process.exit(1); }
console.log("\napplications contract PASSED.");
