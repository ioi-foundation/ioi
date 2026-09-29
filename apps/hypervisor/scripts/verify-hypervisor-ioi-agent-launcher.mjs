#!/usr/bin/env node
// IOI Agent launcher — a RETIREMENT GUARD (R-240, GoalRun residue, 2026-09-29).
//
// This verifier used to prove the IOI Agent launch lane end to end: a goal intake with an
// Auto / Direct / Compare / Private-local strategy selector, a daemon launch-preview planning
// `direct` or `goal_run`, a two-phase wallet launch whose Compare strategy created, started and
// reconciled a GoalRun across two harnesses, and result links into the goal-run timeline and the
// ledger's goal_run kinds. R-192 (S5-1) took goal pursuit out of the Hypervisor, and the standing
// owner ruling (2026-09-24) keeps it out: a goal run is an ioi.ai composition over the Hypervisor's
// thread orchestration primitives, never a Hypervisor plane. Every route it drove is gone, so it
// crashed on its first read. What it proves now is that the lane STAYS gone, on a stack it owns,
// as that stack's signed-in operator:
//   - the daemon mounts nothing for the launch lane: each former route answers 404 to the operator
//     (no handler — the caller is not what is refused), and the daemon's own route index publishes
//     no path under /v1/goal-orchestration/;
//   - the serve's two relays answer the typed 410 `ioi_agent_launch_retired` rather than relaying
//     into a 404;
//   - the owned New Session launcher — the successor, verified end to end by
//     verify-hypervisor-new-session-launcher — opens with no goal-pursuit strategy selector, no
//     launch-policy chooser and no GoalRun language.
//
// Usage: node apps/hypervisor/scripts/verify-hypervisor-ioi-agent-launcher.mjs  (≈1 min)
// Its own isolated daemon + serve, the operator signed in (lib/verifier-stack.mjs); an explicit
// URL naming the owner's stack (:8765, :36173, :4173) is refused.

import { chromium } from "playwright";
import { verifierStack } from "./lib/verifier-stack.mjs";

const STACK = await verifierStack({ serve: true });
const DAEMON = STACK.daemonUrl;
const SHELL = STACK.serveUrl;

const results = [];
const ok = (name, cond, detail) => { results.push({ name, pass: !!cond, detail: detail || "" }); };
async function jd(method, url, body) {
  const r = await fetch(url, {
    method,
    headers: { "content-type": "application/json" },
    body: body ? JSON.stringify(body) : undefined,
  }).catch(() => null);
  const text = r ? await r.text().catch(() => "") : "";
  let j = null; try { j = JSON.parse(text); } catch { j = null; }
  return { status: r?.status ?? 0, j, text };
}

async function run() {
  // ── The daemon mounts nothing for the launch lane ──
  const retired = [
    ["POST", "/v1/goal-orchestration/ioi-agent/launch-preview", { goal: "Create a tiny hello file", strategy: "auto" }],
    ["POST", "/v1/goal-orchestration/ioi-agent/launch", { goal: "Create a tiny hello file", strategy: "compare" }],
    ["GET", "/v1/goal-orchestration/ioi-agent/launches", null],
    ["GET", "/v1/goal-orchestration/goal-runs", null],
  ];
  const answers = [];
  for (const [method, p, body] of retired) answers.push({ p, method, ...(await jd(method, `${DAEMON}${p}`, body)) });
  ok("the daemon answers every former launch-lane route 404 to the signed-in operator (no handler, not a refused caller)",
    answers.every((a) => a.status === 404),
    answers.map((a) => `${a.method} ${a.p.split("/").slice(-2).join("/")}=${a.status}`).join(" "));
  const index = await jd("GET", `${DAEMON}/v1`);
  const indexPaths = (Array.isArray(index.j?.families) ? index.j.families : []).flatMap((f) => (Array.isArray(f.paths) ? f.paths : [])).map((r) => String(r.path || ""));
  ok("the daemon's own route index publishes no path under /v1/goal-orchestration/",
    index.status === 200 && indexPaths.length > 0 && !indexPaths.some((p) => p.startsWith("/v1/goal-orchestration/")),
    `${indexPaths.length} paths indexed`);

  // ── The serve's relays answer a typed retirement ──
  const relays = [];
  for (const p of ["/__ioi/api/ioi-agent/preview", "/__ioi/api/ioi-agent/launch"]) {
    relays.push({ p, ...(await jd("POST", `${SHELL}${p}`, { goal: "Create a tiny hello file", strategy: "direct" })) });
  }
  ok("the serve's preview and launch relays answer 410 ioi_agent_launch_retired, never a relayed 404",
    relays.every((r) => r.status === 410 && r.j?.error?.code === "ioi_agent_launch_retired" && /ioi\.ai composition/.test(r.j?.error?.message || "")),
    relays.map((r) => `${r.p.split("/").pop()}=${r.status}/${r.j?.error?.code}`).join(" "));

  // ── The successor launcher carries none of it ──
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1600, height: 1000 } });
  await STACK.signIn(page);
  const pageErrors = [];
  page.on("pageerror", (e) => pageErrors.push(String(e)));
  await page.goto(`${SHELL}/`, { waitUntil: "domcontentloaded" });
  await page.waitForSelector('[data-testid="sidebar"]', { timeout: 60000 });
  await page.click('[data-testid="create-session-button"]');
  // New Session routes to the composer page; the owned modal opens via Advanced launch.
  await page.waitForSelector("#ioi-ns-advanced", { timeout: 60000 });
  await page.click("#ioi-ns-advanced");
  await page.waitForSelector("#ioi-ns-modal.open #ioi-ns-launch", { timeout: 60000 });
  const header = (await page.locator("#ioi-ns-modal .ioi-mh span").first().textContent()) || "";
  const bodyText = await page.locator("#ioi-ns-modal").innerText();
  const strategySelects = await page.locator("#ioi-ns-strategy").count();
  const policySelects = await page.locator("#ioi-ns-policy").count();
  ok("the New Session launcher opens as New Session with no strategy selector and no launch-policy chooser",
    /New Session/.test(header) && strategySelects === 0 && policySelects === 0,
    `header=${header.trim()} strategy=${strategySelects} policy=${policySelects}`);
  ok("the launcher names no GoalRun and no IOI Agent coordination",
    !/GoalRun|goal run|IOI Agent will coordinate|compare across harnesses/i.test(bodyText),
    bodyText.split("\n").slice(0, 3).join(" | "));
  ok("no page errors across the launcher", pageErrors.length === 0, pageErrors.slice(0, 2).join(" | "));
  await browser.close();
}

run().then(() => {
  let fail = 0;
  for (const r of results) { console.log(`  ${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? `  (${r.detail})` : ""}`); if (!r.pass) fail++; }
  console.log(`\n${results.length - fail}/${results.length} passed`);
  console.log(`ioi-agent launcher retirement: ${fail ? "FAIL" : "OK"}`);
  process.exit(fail ? 1 : 0);
}).catch((e) => {
  console.error("verifier crashed:", e);
  process.exit(1);
});
