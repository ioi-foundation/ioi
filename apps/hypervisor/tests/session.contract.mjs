#!/usr/bin/env node
// Behavioral contract test — source-owned Session detail / Workspace surface (cut 4 gate).
// Asserts the conversation/run-timeline renders the daemon's REAL turns from the native threads
// plane (GET /v1/threads/:id + its runtime event stream), with NO upstream-namespace wire bridge.
// Deterministic via route mocking. Requires the vite dev server on :1420.
// Run: node apps/hypervisor/tests/session.contract.mjs
import { chromium } from "playwright";

const BASE = process.env.APP_URL || "http://127.0.0.1:1420";
const fails = [];
const ok = (n) => console.log(`  ✓ ${n}`);
const bad = (n, d) => { fails.push(n); console.error(`  ✗ ${n}${d ? " — " + d : ""}`); };

const TID = "thread_demo_1";

const THREAD = {
  thread_id: TID,
  title: "Wire the Session surface",
  status: "active",
  updated_at: new Date(Date.now() - 1800e3).toISOString(),
  workspace: ".",
};

// Two turns folded from a daemon SSE runtime event stream: a turn that starts, streams an
// assistant delta, runs an item, and completes; plus a second running turn with a prompt.
const sse = [
  { seq: 1, actor: "runtime", event_kind: "thread.started", turn_id: null, payload_summary: { status: "active" } },
  { seq: 2, actor: "runtime", event_kind: "turn.started", turn_id: "turn_a", payload_summary: { prompt: "Refactor the parser" } },
  { seq: 3, actor: "runtime", event_kind: "item.runtime_task", turn_id: "turn_a", payload_summary: { event_type: "runtime_task" } },
  { seq: 4, actor: "assistant", event_kind: "item.delta", turn_id: "turn_a", payload_summary: { text: "Done refactoring the parser." } },
  { seq: 5, actor: "runtime", event_kind: "turn.completed", turn_id: "turn_a", payload_summary: { result: "Done refactoring the parser." } },
  { seq: 6, actor: "runtime", event_kind: "turn.started", turn_id: "turn_b", payload_summary: { prompt: "Now add tests" } },
]
  .map((e) => `id: ${e.event_kind}\nevent: runtime.event\ndata: ${JSON.stringify(e)}\n`)
  .join("\n");

async function run(scenario) {
  const browser = await chromium.launch();
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 }, colorScheme: "dark" });
  const page = await ctx.newPage();
  const seen = [];
  await page.route("**/v1/**", (route) => {
    const u = route.request().url();
    const p = u.replace(/^https?:\/\/[^/]+/, "");
    seen.push(p);
    if (scenario === "error" && p.includes(`/v1/threads/${TID}`) && !p.includes("/events")) {
      return route.fulfill({ status: 500, contentType: "application/json", body: JSON.stringify({ error: "boom" }) });
    }
    if (p.includes(`/v1/threads/${TID}/events`)) {
      const body = scenario === "empty" ? "" : sse;
      return route.fulfill({ status: 200, contentType: "text/event-stream", body });
    }
    if (p.includes(`/v1/threads/${TID}`)) {
      return route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(THREAD) });
    }
    if (p.includes("/v1/threads")) {
      return route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ threads: [THREAD] }) });
    }
    return route.fulfill({ status: 200, contentType: "application/json", body: "{}" });
  });
  await page.route("**/api/**", (route) => {
    seen.push(route.request().url().replace(/^https?:\/\/[^/]+/, ""));
    route.fulfill({ status: 404, body: "" });
  });

  await page.goto(`${BASE}/sessions/${TID}`, { waitUntil: "networkidle" });
  await page.waitForTimeout(700);
  return { browser, page, seen };
}

// ── Scenario: full timeline ──────────────────────────────────────────────────────────────────────
{
  const { browser, page, seen } = await run("full");
  const m = await page.evaluate(() => ({
    header: !!document.querySelector("[data-testid=session-header]"),
    title: document.querySelector(".se-title")?.textContent,
    timeline: !!document.querySelector("[data-testid=session-timeline]"),
    turns: document.querySelectorAll("[data-testid=session-turn]").length,
    prompts: [...document.querySelectorAll("[data-testid=session-turn-prompt]")].map((e) => e.textContent?.trim()),
    replies: [...document.querySelectorAll("[data-testid=session-turn-reply]")].map((e) => e.textContent?.trim()),
    workspace: !!document.querySelector("[data-testid=session-workspace]"),
  }));

  m.header ? ok("session header present") : bad("session header");
  m.title === "Wire the Session surface" ? ok("real thread title in header") : bad("thread title", m.title);
  m.timeline ? ok("timeline region present") : bad("timeline region");
  m.turns === 2 ? ok("two turns folded from event stream") : bad("turns", `got ${m.turns}`);
  m.prompts.includes("Refactor the parser") && m.prompts.includes("Now add tests")
    ? ok("turn prompts render from daemon events")
    : bad("turn prompts", m.prompts.join(" | "));
  m.replies.some((r) => (r || "").includes("Done refactoring the parser"))
    ? ok("assistant reply rendered from delta/completed")
    : bad("turn reply", m.replies.join(" | "));
  m.workspace ? ok("workspace (workbench) mounted") : bad("workspace mount");

  const native = seen.some((s) => s.includes(`/v1/threads/${TID}`)) && seen.some((s) => s.includes("/events"));
  const bridged = seen.some((s) => /\/api\/[a-z][a-z0-9.]*\.v\d+\//i.test(s));
  native ? ok("uses native /v1/threads/:id + events") : bad("native threads plane", seen.join(","));
  !bridged ? ok("no upstream-wire bridge") : bad("no upstream-wire bridge");

  await browser.close();
}

// ── Scenario: empty (thread with no turns) ────────────────────────────────────────────────────────
{
  const { browser, page } = await run("empty");
  const empty = await page.evaluate(() => ({
    header: !!document.querySelector("[data-testid=session-header]"),
    emptyState: !!document.querySelector("[data-testid=session-empty]"),
    turns: document.querySelectorAll("[data-testid=session-turn]").length,
  }));
  empty.header ? ok("empty: header still renders") : bad("empty: header");
  empty.emptyState && empty.turns === 0 ? ok("empty: honest empty state, no turns") : bad("empty state", JSON.stringify(empty));
  await browser.close();
}

// ── Scenario: daemon error ─────────────────────────────────────────────────────────────────────────
{
  const { browser, page } = await run("error");
  const err = await page.evaluate(() => !!document.querySelector("[data-testid=session-error]"));
  err ? ok("error: error state renders") : bad("error state");
  await browser.close();
}

if (fails.length) { console.error(`\nsession contract FAILED: ${fails.length}`); process.exit(1); }
console.log("\nsession contract PASSED.");
