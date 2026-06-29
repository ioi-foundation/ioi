#!/usr/bin/env node
// Behavioral contract test — source-owned New automation surface (/automations/new).
// Asserts the native daemon create contract (protocol-native: no upstream wire), the form
// landmarks (name, trigger kinds, steps), an honest daemon-backed create (POST body shape +
// success receipt from the daemon's own record), and the error state. Deterministic via route
// mocking — no daemon state is mutated.
//
// Requires the vite dev server on :1420 with /automations/new wired to AutomationNewView.
// Run: node apps/hypervisor/tests/automation-new.contract.mjs
import { chromium } from "playwright";

const BASE = process.env.APP_URL || "http://127.0.0.1:1420";
const fails = [];
const ok = (name) => console.log(`  ✓ ${name}`);
const bad = (name, detail) => { fails.push(name); console.error(`  ✗ ${name}${detail ? " — " + detail : ""}`); };

const browser = await chromium.launch();

// `post` lets a test fulfill a POST with a body it controls + capture the request body the surface sent.
async function withPage({ post } = {}, fn) {
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 }, colorScheme: "dark" });
  const page = await ctx.newPage();
  const seen = [];
  const posts = [];
  await page.route("**/v1/**", (route) => {
    const req = route.request();
    const url = req.url().replace(/^https?:\/\/[^/]+/, "");
    seen.push(url);
    if (req.method() === "POST" && url.includes("/hypervisor/automations")) {
      let body = {};
      try { body = JSON.parse(req.postData() || "{}"); } catch { /* */ }
      posts.push(body);
      return route.fulfill(post || { status: 200, contentType: "application/json", body: JSON.stringify({ ok: true, automation: { automation_id: "auto_created", name: body.name, trigger: body.trigger, steps: body.steps || [], environment_class_id: "local-workspace-v0" } }) });
    }
    return route.fulfill({ status: 200, contentType: "application/json", body: "{}" });
  });
  await page.route("**/api/**", (route) => { seen.push(route.request().url().replace(/^https?:\/\/[^/]+/, "")); route.fulfill({ status: 404, body: "" }); });
  await fn(page, seen, posts);
  await ctx.close();
}

// --- Test A: form landmarks render ---
await withPage({}, async (page, seen) => {
  await page.goto(`${BASE}/automations/new`, { waitUntil: "networkidle" });
  await page.waitForTimeout(400);
  const m = await page.evaluate(() => ({
    pageL: !!document.querySelector("[data-testid=automation-new-page]"),
    back: !!document.querySelector("[data-testid=automation-new-back]"),
    form: !!document.querySelector("[data-testid=automation-new-form]"),
    name: !!document.querySelector("[data-testid=automation-name]"),
    triggers: document.querySelectorAll("[data-testid^=automation-trigger-]").length,
    manual: !!document.querySelector("[data-testid=automation-trigger-manual]"),
    schedule: !!document.querySelector("[data-testid=automation-trigger-schedule]"),
    event: !!document.querySelector("[data-testid=automation-trigger-event]"),
    steps: document.querySelectorAll("[data-testid=automation-step]").length,
    submit: !!document.querySelector("[data-testid=automation-submit]"),
  }));
  m.pageL ? ok("renders automation-new-page landmark") : bad("automation-new-page landmark");
  m.back ? ok("back link present") : bad("back link");
  m.form ? ok("create form present") : bad("create form");
  m.name ? ok("name field present") : bad("name field");
  m.triggers === 3 && m.manual && m.schedule && m.event ? ok("3 trigger kinds (manual/schedule/event)") : bad("trigger kinds", `got ${m.triggers}`);
  m.steps === 1 ? ok("seeds 1 step row") : bad("initial step", `got ${m.steps}`);
  m.submit ? ok("submit button present") : bad("submit button");
  // No GET should hit the upstream wire either.
  const bridged = seen.filter((s) => /\/api\/[a-z][a-z0-9.]*\.v\d+\//i.test(s));
  bridged.length === 0 ? ok("no upstream-wire bridge (no /api/<pkg>.vN/ calls)") : bad("no upstream-wire bridge", bridged.join(","));
});

// --- Test B: cron trigger reveals cron input + add step ---
await withPage({}, async (page) => {
  await page.goto(`${BASE}/automations/new`, { waitUntil: "networkidle" });
  await page.waitForTimeout(300);
  await page.click("[data-testid=automation-trigger-schedule]");
  await page.waitForTimeout(150);
  (await page.locator("[data-testid=automation-cron]").count()) ? ok("schedule trigger reveals cron input") : bad("cron input");
  await page.click("[data-testid=automation-add-step]");
  await page.waitForTimeout(150);
  (await page.locator("[data-testid=automation-step]").count()) === 2 ? ok("add step grows the step list") : bad("add step");
});

// --- Test C: submit → native POST contract (body shape) + success receipt from daemon record ---
await withPage({}, async (page, seen, posts) => {
  await page.goto(`${BASE}/automations/new`, { waitUntil: "networkidle" });
  await page.waitForTimeout(300);
  await page.fill("[data-testid=automation-name]", "nightly-changelog");
  await page.click("[data-testid=automation-trigger-schedule]");
  await page.fill("[data-testid=automation-cron]", "0 2 * * *");
  await page.fill("[data-testid=automation-step-value]", "Summarize changes");
  await page.click("[data-testid=automation-submit]");
  await page.waitForTimeout(500);
  posts.length > 0 && seen.some((s) => s.includes("/v1/hypervisor/automations")) ? ok("POSTs /v1/hypervisor/automations") : bad("POST automations", "not requested");
  const body = posts[0] || {};
  body.name === "nightly-changelog" ? ok("POST carries name") : bad("POST name", JSON.stringify(body));
  body.trigger?.kind === "schedule" && body.trigger?.cron === "0 2 * * *" ? ok("POST carries cron trigger") : bad("POST trigger", JSON.stringify(body.trigger));
  Array.isArray(body.steps) && body.steps[0]?.kind === "agent" && body.steps[0]?.prompt === "Summarize changes" ? ok("POST carries typed step") : bad("POST steps", JSON.stringify(body.steps));
  (await page.locator("[data-testid=automation-new-success]").count()) ? ok("renders success receipt") : bad("success receipt");
  (await page.locator("[data-testid=automation-new-receipt]").count()) ? ok("receipt shows daemon-returned record") : bad("receipt block");
});

// --- Test D: daemon error → honest error state (no fabricated success) ---
await withPage({ post: { status: 502, contentType: "application/json", body: JSON.stringify({ ok: false, reason: "daemon unavailable" }) } }, async (page) => {
  await page.goto(`${BASE}/automations/new`, { waitUntil: "networkidle" });
  await page.waitForTimeout(300);
  await page.fill("[data-testid=automation-name]", "x");
  await page.fill("[data-testid=automation-step-value]", "do thing");
  await page.click("[data-testid=automation-submit]");
  await page.waitForTimeout(400);
  (await page.locator("[data-testid=automation-new-error]").count()) ? ok("daemon error surfaces (no fabricated success)") : bad("error state");
  (await page.locator("[data-testid=automation-new-success]").count()) === 0 ? ok("no success receipt on failure") : bad("false success on failure");
});

await browser.close();
if (fails.length) { console.error(`\nautomation-new contract FAILED: ${fails.length} assertion(s)`); process.exit(1); }
console.log("\nautomation-new contract PASSED.");
