// R-240 Arm A — the New Session launcher's default path is never a refusal.
//
// The launcher preselected the registry default harness (the native worker) from its STORED runnability, which read
// "not probed" as selectable. On a plane with no reachable model upstream the bind's LIVE probe refuses it, so a person
// who opened the launcher and pressed Start without touching anything got "Launch rejected fail-closed —
// harness_profile_not_runnable". The launcher now reads the same live probe (the daemon's answer) and preselects only a
// harness that runs over an available route; with none it preselects None and says why under the select, before Start.
//
// LIVE, on an isolated daemon + serve whose model upstream is a closed port, in a headless browser signed in as the
// plane's operator: the launcher's default, the reason it gives, and a Start pressed with nothing changed.
//
//   IOI_HYPERVISOR_DAEMON_BINARY=<daemon> node --test apps/hypervisor/scripts/new-session-default-harness.test.mjs
import test, { after } from "node:test";
import assert from "node:assert/strict";
import { isolatedOperatorSession, startIsolatedPlane } from "./lib/isolated-daemon.mjs";

const cleanups = [];
after(async () => { for (const fn of cleanups.reverse()) await fn().catch(() => {}); });

test("LIVE: with no runnable harness the launcher defaults to None, says why, and Start creates the session", { timeout: 900_000 }, async (t) => {
  const baseEnv = Object.fromEntries(Object.entries(process.env).filter(([k]) => !k.startsWith("IOI_") || k === "IOI_HYPERVISOR_DAEMON_BINARY"));
  const plane = await startIsolatedPlane({ serve: true, baseEnv, env: { IOI_HYPERVISOR_MODEL_UPSTREAM: "http://127.0.0.1:1/v1" } });
  if (!plane) { t.skip("BLOCKED: no daemon binary"); return; }
  cleanups.push(() => plane.stop());
  const token = await isolatedOperatorSession(plane);
  const cookie = `ioi_session=${token}`;

  // The context carries the daemon's live answer: the worker cannot run here, and says why.
  const ctx = await fetch(`${plane.serveUrl}/__ioi/api/new-session/context`, { headers: { cookie } }).then((r) => r.json());
  const worker = (ctx.harness_profiles || []).find((p) => p.default);
  assert.ok(worker, "the registry names a default harness");
  assert.equal(worker.runnability_live, true, "the launcher read the live probe");
  assert.equal(worker.runnability_state, "model_route_unreachable");

  const { chromium } = await import("playwright");
  const browser = await chromium.launch({ headless: true });
  cleanups.push(() => browser.close());
  const context = await browser.newContext({ viewport: { width: 1500, height: 1000 } });
  await context.addCookies([{ name: "ioi_session", value: token, url: plane.serveUrl }]);
  const tab = await context.newPage();
  await tab.goto(`${plane.serveUrl}/ai#new-session`, { waitUntil: "domcontentloaded", timeout: 300_000 });
  await tab.waitForSelector("#ioi-ns-advanced", { timeout: 300_000 });
  await tab.click("#ioi-ns-advanced");
  await tab.waitForSelector("#ioi-ns-modal.open #ioi-ns-launch", { timeout: 300_000 });

  // The default is None, the worker is offered disabled WITH its reason, and the reason is said before Start.
  assert.equal(await tab.inputValue("#ioi-ns-harness"), "", "no harness is preselected when none can run");
  assert.equal(await tab.getAttribute("#ioi-ns-harness", "data-ioi-harness-default"), "none");
  const workerOption = await tab.locator(`#ioi-ns-harness option[value="${worker.profile_ref}"]`).evaluate((o) => ({ disabled: o.disabled, text: o.textContent }));
  assert.equal(workerOption.disabled, true);
  assert.match(workerOption.text, /model_route_unreachable/u);
  const why = tab.locator("#ioi-ns-harness-why");
  assert.equal(await why.isVisible(), true, "the launcher says why before Start");
  assert.match(await why.innerText(), /No harness can run on this host right now/u);
  assert.equal(await tab.getAttribute("#ioi-ns-launch", "aria-disabled"), null, "Start is live: None is a launch the daemon admits");

  // Start with nothing changed (a fresh workspace: this plane holds no project) creates the session.
  await tab.click('[data-ns-branch="scratch"]');
  await tab.click("#ioi-ns-launch");
  await tab.waitForFunction(() => /Session created|rejected|did not reach/u.test(document.querySelector("#ioi-ns-result")?.textContent || ""), null, { timeout: 600_000 });
  const said = await tab.locator("#ioi-ns-result").innerText();
  assert.match(said, /Session created/u, said.slice(0, 200));
  assert.doesNotMatch(said, /harness_profile_not_runnable/u);
  const sessionRef = (said.match(/session:hyp-[0-9a-f]+/u) || [])[0];
  assert.ok(sessionRef, "the result names the session");
  const record = await fetch(`${plane.daemonUrl}/v1/hypervisor/sessions/${encodeURIComponent(sessionRef)}`, { headers: { cookie } }).then((r) => r.json());
  const session = record.session || record;
  assert.equal(session.session_ref, sessionRef);
  assert.ok(!session.harness_binding, "the session carries no harness binding (the execute-time default)");
});
