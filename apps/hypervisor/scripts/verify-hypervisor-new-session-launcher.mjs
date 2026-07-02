#!/usr/bin/env node
// New Session launcher done-bar verifier (02-new-session graft).
//
// Drives the OWNED rail-modal launcher end-to-end: the daemon-backed context endpoint (real
// projects / recent environments / registry-derived harness matrix / model routes — nothing
// fabricated), the fail-closed launch lane (inadmissible harness selections abort the create with
// the planner/registry error), and the in-shell Playwright flow — rail create-session action opens
// the owned modal, three intake branches, harness/model selects where unavailable options are
// DISABLED WITH THEIR REASON (never hidden), knob options filtered to the chosen harness's
// registry capability matrix, a launch preview naming admission + receipts + isolation + restore
// BEFORE the effectful call, URL-branch validation, and a real launch whose result names the
// session ref, provision receipt, harness admission, and capability-admitted knob binding.
//
// Usage: node apps/hypervisor/scripts/verify-hypervisor-new-session-launcher.mjs
// Exit 0 = all assertions pass. Creates one real session (daemon estate truth, intentionally kept).

import { chromium } from "playwright";

const SHELL = (process.env.IOI_HYPERVISOR_APP_URL || "http://127.0.0.1:4173").replace(/\/$/, "");

const results = [];
const ok = (name, cond, detail) => { results.push({ name, pass: !!cond, detail: detail || "" }); };
async function jd(method, path, body) {
  const r = await fetch(`${SHELL}${path}`, { method, headers: { "content-type": "application/json" }, body: body ? JSON.stringify(body) : undefined });
  const t = await r.text();
  let j = null; try { j = JSON.parse(t); } catch { /* non-json */ }
  return { status: r.status, j };
}

async function run() {
  // 1. Context endpoint: daemon-backed truth, honest shapes.
  const ctx = await jd("GET", "/__ioi/api/new-session/context");
  const profiles = ctx.j?.harness_profiles || [];
  ok("context carries the registry harness matrix", profiles.length >= 6 && profiles.every((p) => p.profile_ref && p.lifecycle_status && p.execution_wiring), `${profiles.length} profiles`);
  ok("context carries model routes with availability posture", (ctx.j?.model_routes || []).length >= 1 && ctx.j.model_routes.every((r) => r.route_ref && r.availability !== undefined), ctx.j?.default_route_ref);
  ok("context carries projects + recent environments", Array.isArray(ctx.j?.projects) && Array.isArray(ctx.j?.environments));

  // 2. Launch lane is FAIL-CLOSED end-to-end: an inadmissible harness selection aborts the create.
  const bad = await jd("POST", "/__ioi/api/new-session/launch", { harness_profile_ref: "harness-profile:hp_deepseek_tui" });
  ok("inadmissible harness selection aborts the launch with the registry error", bad.status >= 400 && bad.j?.error?.code === "harness_profile_not_active", bad.j?.error?.code);

  // 3. In-shell modal flow.
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1600, height: 1000 } });
  const consoleErrors = [];
  const failedUrls = [];
  page.on("requestfailed", (r) => failedUrls.push(r.url()));
  page.on("console", (m) => {
    if (m.type() !== "error") return;
    // Known pre-existing shell artifact: the SPA home changelog references an external docs
    // domain that does not resolve; unrelated to this surface.
    if (/Failed to load resource/.test(m.text()) && failedUrls.every((u) => u.startsWith("https://docs.ioi.com/"))) return;
    consoleErrors.push(m.text());
  });
  page.on("pageerror", (e) => consoleErrors.push(String(e)));

  await page.goto(`${SHELL}/`, { waitUntil: "domcontentloaded" });
  await page.waitForSelector('[data-testid="sidebar"]', { timeout: 20000 });
  await page.click('[data-testid="create-session-button"]');
  await page.waitForSelector("#ioi-ns-modal.open", { timeout: 10000 });
  ok("rail create-session action opens the owned launcher modal", true);
  const railVisible = await page.locator('[data-testid="sidebar"]').isVisible();
  ok("left rail remains visible behind the modal", railVisible);

  await page.waitForSelector("#ioi-ns-harness", { timeout: 10000 });
  const tabs = await page.locator("#ioi-ns-modal .ioi-ns-tab").allTextContents();
  ok("three intake branches (project / URL / scratch)", tabs.length === 3 && /project/i.test(tabs[0]) && /URL/i.test(tabs[1]) && /scratch/i.test(tabs[2]), tabs.join(" | "));

  // Harness select: registry options; unavailable = disabled WITH reason, never hidden.
  const hpOptions = await page.locator("#ioi-ns-harness option").evaluateAll((os) => os.map((o) => ({ v: o.value, t: o.textContent, d: o.disabled })));
  ok("harness select lists the full registry (+ explicit none option)", hpOptions.length === 7 && hpOptions[0].v === "", `${hpOptions.length} options`);
  const dsOpt = hpOptions.find((o) => /DeepSeek/i.test(o.t));
  ok("unavailable harness shown disabled WITH its reason (not hidden)", dsOpt && dsOpt.d === true && /not enabled|adapter slot|not runnable/i.test(dsOpt.t), dsOpt?.t);
  const workerOpt = hpOptions.find((o) => /Hypervisor Worker/i.test(o.t));
  ok("runnable lane-A worker is selectable and preselected as default", workerOpt && workerOpt.d === false && (await page.locator("#ioi-ns-harness").inputValue()) === workerOpt.v, workerOpt?.t);

  // Knob options come from the chosen harness's registry capability matrix.
  const reasoningOpts = await page.locator("#ioi-ns-reasoning option").allTextContents();
  const speedOpts = await page.locator("#ioi-ns-speed option").allTextContents();
  ok("reasoning options = worker capability matrix", reasoningOpts.join(",") === "low,medium,high", reasoningOpts.join(","));
  ok("speed options = worker capability matrix", speedOpts.join(",") === "fast,balanced,thorough", speedOpts.join(","));

  // Launch preview names the governed contract BEFORE any effectful call.
  const preview = await page.locator("#ioi-ns-preview").innerText();
  ok("preview names the admission before launch", /bind_session_profile/.test(preview) && /scope:harness\.profile\.mutate/.test(preview));
  ok("preview names receipts + isolation + restore path", /session-provision/.test(preview) && /Isolation/i.test(preview) && /Restore/i.test(preview));

  // URL branch validates before firing.
  await page.click('[data-ns-branch="url"]');
  await page.fill("#ioi-ns-url", "not-a-url");
  await page.click("#ioi-ns-launch");
  const urlErr = await page.locator("#ioi-ns-result .ioi-ns-err").innerText();
  ok("URL branch validates input (no effectful call on bad input)", /valid http/i.test(urlErr), urlErr.slice(0, 60));

  // Real launch from scratch with the default harness + route.
  await page.click('[data-ns-branch="scratch"]');
  await page.click("#ioi-ns-launch");
  await page.waitForFunction(() => /Session created|rejected/.test(document.querySelector("#ioi-ns-result")?.textContent || ""), null, { timeout: 30000 });
  const resultText = await page.locator("#ioi-ns-result").innerText();
  ok("launch creates a real session", /Session created/.test(resultText), resultText.slice(0, 60));
  ok("result names the session + provision receipt", /session:hyp-/.test(resultText) && /receipt:\/\/hypervisor\/session-provision\//.test(resultText));
  ok("result names the admitted harness binding", /harness-profile:hp_hypervisor_worker/.test(resultText) && /harness-profile-mutation-admission:/.test(resultText));
  ok("result names the capability-admitted knobs", /reasoning/i.test(resultText) && /agentgres:\/\/harness-binding\//.test(resultText));
  ok("result offers the Workbench handoff", await page.locator('#ioi-ns-result a[href="/__ioi/workbench"]').count() >= 1);

  // The created session is DAEMON truth, not UI state.
  const m = resultText.match(/session:hyp-[a-z0-9]+/);
  if (m) {
    const daemon = (process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765").replace(/\/$/, "");
    const sess = await fetch(`${daemon}/v1/hypervisor/sessions/${encodeURIComponent(m[0])}`).then((r) => r.json()).catch(() => ({}));
    const rec = sess.session || sess;
    ok("created session exists in the daemon with the recorded harness binding", rec?.session_ref === m[0] && rec?.harness_binding?.profile_ref === "harness-profile:hp_hypervisor_worker", rec?.harness_binding?.binding_id);
  } else {
    ok("created session exists in the daemon with the recorded harness binding", false, "no session ref parsed");
  }

  const shot = process.env.IOI_NS_SCREENSHOT;
  if (shot) await page.screenshot({ path: shot, fullPage: false });
  ok("no console errors", consoleErrors.length === 0, consoleErrors.slice(0, 3).join(" | "));
  await browser.close();
}

run().then(() => {
  let fail = 0;
  for (const r of results) { console.log(`  ${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? `  (${r.detail})` : ""}`); if (!r.pass) fail++; }
  console.log(`\n${results.length - fail}/${results.length} passed`);
  console.log(`new-session launcher readiness: ${fail ? "FAIL" : "OK"}`);
  process.exit(fail ? 1 : 0);
}).catch((e) => {
  console.error("verifier crashed:", e);
  process.exit(1);
});
