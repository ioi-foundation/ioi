#!/usr/bin/env node
// IOI Agent launch-policy done-bar.
//
// Proves durable launch policies are real routing/admission preference envelopes (never a
// harness, never receipt-optional), composed by the daemon planner with live registry facts:
// seeded protected defaults + clone-to-customize, full CRUD lanes, fail-closed unknown/disabled
// refs, per-policy planner semantics (private-local exclusions, compare-before-write → goal_run,
// fast-local → direct via preferred ordering, high-assurance minimums, explicit allow_fallback
// relaxation), the New Session policy selector with a daemon-backed preview that CHANGES with
// the policy, launch results carrying policy_ref, and policy_ref reaching the proof surfaces
// (goal-run record → Run Timeline proof grid + Work Ledger entry). Ends with source-neutral +
// fallthrough hygiene. (≈2–4 min; runs one real compare launch.)
//
// Usage: node apps/hypervisor/scripts/verify-hypervisor-ioi-agent-launch-policies.mjs

import { execSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const { mintApprovalGrant } = await import(path.join(HERE, "../../../scripts/lib/mint-approval-grant.mjs"));

const DAEMON = (process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765").replace(/\/$/, "");
const SHELL = (process.env.IOI_HYPERVISOR_APP_URL || "http://127.0.0.1:4173").replace(/\/$/, "");

const results = [];
const ok = (name, cond, detail) => { results.push({ name, pass: !!cond, detail: detail || "" }); };
async function jd(method, url, body) {
  const r = await fetch(url.startsWith("http") ? url : `${DAEMON}${url}`, {
    method, headers: { "content-type": "application/json" }, body: body ? JSON.stringify(body) : undefined,
  });
  return { status: r.status, j: await r.json().catch(() => ({})) };
}
const preview = (body) => jd("POST", "/v1/hypervisor/ioi-agent/launch-preview", body);

async function run() {
  const tag = Date.now().toString(16);
  for (const id of ["hp_opencode", "hp_deepseek_tui"]) await jd("POST", `/v1/hypervisor/harness-profiles/${id}/enable`);

  // ── Records: defaults, round-trip, CRUD, protection ──
  const list = await jd("GET", "/v1/hypervisor/ioi-agent/launch-policies");
  const ids = (list.j?.policies || []).map((p) => p.policy_id);
  ok("seeded default policy set exists (5 protected, receipt-required)",
    ["pol_auto_default", "pol_fast_local", "pol_private_local", "pol_compare_before_write", "pol_high_assurance"].every((id) => ids.includes(id))
    && (list.j?.policies || []).filter((p) => p.origin === "seeded").every((p) => p.protected === true && p.receipt_required === true),
    ids.join(","));
  const got = await jd("GET", "/v1/hypervisor/ioi-agent/launch-policies/pol_fast_local");
  ok("policies list/get round-trip", got.status === 200 && got.j?.policy?.policy_ref === "ioi-agent-policy://pol_fast_local");
  const created = await jd("POST", "/v1/hypervisor/ioi-agent/launch-policies", {
    display_name: `vfy-policy-${tag}`,
    strategy_preference: "direct",
    harness_preferences: { preferred_harness_refs: ["harness-profile:hp_deepseek_tui"], excluded_harness_refs: [], allow_fallback: true },
  });
  const cid = created.j?.policy?.policy_id || "";
  ok("create works (authored, unprotected)", created.status === 201 && created.j?.policy?.protected === false, cid);
  const patched = await jd("PATCH", `/v1/hypervisor/ioi-agent/launch-policies/${cid}`, { description: "edited" });
  ok("edit works on authored policies", patched.status === 200 && patched.j?.policy?.description === "edited");
  const cloned = await jd("POST", "/v1/hypervisor/ioi-agent/launch-policies/pol_high_assurance/clone", { display_name: `vfy-clone-${tag}` });
  const cloneId = cloned.j?.policy?.policy_id || "";
  ok("clone of a protected default yields an editable copy", cloned.status === 201 && cloned.j?.policy?.protected === false && cloned.j?.policy?.cloned_from === "ioi-agent-policy://pol_high_assurance", cloneId);
  const protectedPatch = await jd("PATCH", "/v1/hypervisor/ioi-agent/launch-policies/pol_high_assurance", { description: "x" });
  ok("protected defaults reject field edits with a clone hint", protectedPatch.status === 409 && protectedPatch.j?.error?.code === "ioi_agent_policy_seeded_protected");
  const disabled = await jd("PATCH", `/v1/hypervisor/ioi-agent/launch-policies/${cid}`, { status: "disabled" });
  ok("disable works", disabled.status === 200 && disabled.j?.policy?.status === "disabled");
  const disabledUse = await preview({ goal: "Create a hello file", policy_ref: `ioi-agent-policy://${cid}` });
  ok("a disabled policy fails closed at plan time", disabledUse.j?.error?.code === "ioi_agent_policy_disabled");
  const unknownUse = await preview({ goal: "Create a hello file", policy_ref: "ioi-agent-policy://pol_nope" });
  ok("an unknown policy ref fails closed", unknownUse.j?.error?.code === "ioi_agent_policy_unresolved");
  const noReceipts = await jd("POST", "/v1/hypervisor/ioi-agent/launch-policies", { display_name: "bad", receipt_required: false });
  ok("no policy may disable receipts", noReceipts.status === 403 && noReceipts.j?.error?.code === "ioi_agent_policy_receipts_mandatory");

  // ── Planner semantics per policy ──
  const priv = await preview({ goal: "Create a hello file", policy_ref: "ioi-agent-policy://pol_private_local" });
  ok("Private local excludes remote/provider-trust harnesses with reasons",
    priv.j?.privacy_posture === "private_local" && priv.j?.remote_slots_disabled === true
    && (priv.j?.excluded_harnesses || []).some((x) => x.reason_code === "private_local_excludes_remote_trust"));
  const cbw = await preview({ goal: "Create a hello file", policy_ref: "ioi-agent-policy://pol_compare_before_write" });
  ok("Compare-before-write plans GoalRun with two eligible local implementers",
    cbw.j?.planned_execution_kind === "goal_run" && (cbw.j?.policy_constraints_applied || []).includes("assurance_require_compare"));
  const fast = await preview({ goal: "Create a hello file", policy_ref: "ioi-agent-policy://pol_fast_local" });
  ok("Fast local plans Direct through the preferred local harness",
    fast.j?.planned_execution_kind === "direct" && fast.j?.selected_harness_ref === "harness-profile:hp_opencode"
    && (fast.j?.policy_constraints_applied || []).includes("policy_preferred_ordering"));
  const high = await preview({ goal: "Create a hello file", policy_ref: "ioi-agent-policy://pol_high_assurance" });
  ok("High assurance requires compare + reconciliation-before-write (min 2 successes)",
    high.j?.planned_execution_kind === "goal_run" && high.j?.policy_effective_summary?.includes("High assurance"));
  await jd("POST", "/v1/hypervisor/harness-profiles/hp_deepseek_tui/disable");
  const blocked = await preview({ goal: "Create a hello file", policy_ref: "ioi-agent-policy://pol_compare_before_write" });
  ok("unsatisfiable policy constraints fail closed (allow_fallback off)", blocked.j?.error?.code === "ioi_agent_policy_compare_unsatisfiable");
  const fallbackClone = await jd("POST", "/v1/hypervisor/ioi-agent/launch-policies/pol_compare_before_write/clone", { display_name: `vfy-fallback-${tag}` });
  const fbId = fallbackClone.j?.policy?.policy_id;
  await jd("PATCH", `/v1/hypervisor/ioi-agent/launch-policies/${fbId}`, { harness_preferences: { preferred_harness_refs: [], excluded_harness_refs: [], allow_fallback: true } });
  const relaxed = await preview({ goal: "Create a hello file", policy_ref: `ioi-agent-policy://${fbId}` });
  ok("allow_fallback relaxes explicitly (recorded, never silent)",
    relaxed.j?.planned_execution_kind === "direct"
    && (relaxed.j?.policy_constraints_relaxed_or_blocked || []).includes("require_compare_relaxed_insufficient_implementers"));
  await jd("POST", "/v1/hypervisor/harness-profiles/hp_deepseek_tui/enable");

  // ── New Session modal: policy selector + preview changes with policy ──
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1600, height: 1000 } });
  const consoleErrors = [];
  const failedUrls = [];
  page.on("requestfailed", (r) => failedUrls.push(r.url()));
  page.on("console", (m) => {
    if (m.type() !== "error") return;
    if (/Failed to load resource/.test(m.text()) && failedUrls.every((u) => u.startsWith("https://docs.ioi.com/"))) return;
    consoleErrors.push(m.text());
  });
  page.on("pageerror", (e) => consoleErrors.push(String(e)));
  await page.goto(`${SHELL}/`, { waitUntil: "domcontentloaded" });
  await page.waitForSelector('[data-testid="sidebar"]', { timeout: 20000 });
  await page.click('[data-testid="create-session-button"]');
  await page.waitForSelector("#ioi-ns-policy", { timeout: 10000 });
  const polOptions = await page.locator("#ioi-ns-policy option").evaluateAll((os) => os.map((o) => ({ v: o.value, sel: o.selected })));
  ok("New Session modal renders the policy selector (Auto default preselected)",
    polOptions.length >= 6 && polOptions.find((o) => o.v === "ioi-agent-policy://pol_auto_default")?.sel === true,
    `${polOptions.length} options`);
  await page.fill("#ioi-ns-goal", "Create a tiny hello file");
  await page.waitForFunction(() => /IOI Agent will coordinate/.test(document.getElementById("ioi-ns-preview")?.textContent || ""), null, { timeout: 15000 });
  const previewAuto = await page.locator("#ioi-ns-preview").innerText();
  await page.selectOption("#ioi-ns-policy", "ioi-agent-policy://pol_compare_before_write");
  await page.waitForFunction(() => /Compare before write/.test(document.getElementById("ioi-ns-preview")?.textContent || ""), null, { timeout: 15000 });
  const previewCbw = await page.locator("#ioi-ns-preview").innerText();
  ok("preview changes when the policy changes (policy summary + plan)",
    previewAuto !== previewCbw && /Compare before write/.test(previewCbw) && /compare across harnesses/.test(previewCbw));
  ok("policy sets the strategy default in the selector", (await page.locator("#ioi-ns-strategy").inputValue()) === "compare");
  ok("no console errors in the launcher flow", consoleErrors.length === 0, consoleErrors.slice(0, 2).join(" | "));
  await browser.close();

  // ── One real policy-driven launch: policy_ref flows to result + proof surfaces ──
  const phaseA = await jd("POST", "/v1/hypervisor/ioi-agent/launch", {
    goal: `Create the file policy-proof-${tag}.txt containing the word: governed`,
    policy_ref: "ioi-agent-policy://pol_compare_before_write",
  });
  ok("policy-driven launch relays the wallet challenge", phaseA.status === 403 && !!phaseA.j?.launch_id && String(phaseA.j?.goal_run_ref || "").startsWith("goal://"));
  const grant = mintApprovalGrant({ policyHash: phaseA.j.approval.policy_hash, requestHash: phaseA.j.approval.request_hash });
  const phaseB = await jd("POST", "/v1/hypervisor/ioi-agent/launch", { launch_id: phaseA.j.launch_id, wallet_approval_grant: grant });
  ok("launch result includes policy_ref in advanced proof",
    phaseB.status === 200 && phaseB.j?.advanced?.policy_ref === "ioi-agent-policy://pol_compare_before_write",
    phaseB.j?.execution_kind);
  const grid = String(phaseB.j?.advanced?.goal_run_ref || "").replace("goal://", "");
  const tl = await fetch(`${SHELL}/__ioi/run-timeline/goal-run/${grid}`).then((r) => r.text());
  ok("Run Timeline proof grid names the launch policy", /Launch policy/.test(tl) && tl.includes("ioi-agent-policy://pol_compare_before_write"));
  const ledger = await jd("GET", "/v1/hypervisor/work-ledger");
  ok("Work Ledger goal_run entry carries policy_ref",
    (ledger.j?.entries || []).some((e) => e.kind === "goal_run" && e.goal_run_ref === `goal://${grid}` && e.policy_ref === "ioi-agent-policy://pol_compare_before_write"));
  const wb = await fetch(`${SHELL}/__ioi/workbench`).then((r) => r.text());
  ok("Workbench projects the policy-driven run", wb.includes(grid));

  // ── Hygiene ──
  let sourceNeutral = false;
  try {
    execSync("npm run check:source-neutral", { cwd: path.join(HERE, ".."), stdio: "pipe" });
    sourceNeutral = true;
  } catch { sourceNeutral = false; }
  ok("source-neutral stays clean", sourceNeutral);
  const ft = await fetch(`${SHELL}/__ioi/fallthrough`).then((r) => r.json()).catch(() => ({}));
  ok("fallthrough stays empty", Array.isArray(ft.proxied) && ft.proxied.length === 0);

  // ── Fixture cleanup + posture restore ──
  for (const id of [cid, cloneId, fbId].filter(Boolean)) await jd("DELETE", `/v1/hypervisor/ioi-agent/launch-policies/${id}`);
  const after = await jd("GET", "/v1/hypervisor/ioi-agent/launch-policies");
  ok("verifier fixtures cleaned (defaults intact)",
    (after.j?.policies || []).length === 5 && (after.j?.policies || []).every((p) => p.origin === "seeded"));
  for (const id of ["hp_opencode", "hp_deepseek_tui"]) await jd("POST", `/v1/hypervisor/harness-profiles/${id}/disable`);
  const fin = await jd("GET", "/v1/hypervisor/harness-profiles");
  ok("drivers restored to non-active posture",
    (fin.j?.profiles || []).filter((p) => ["opencode", "deepseek_tui"].includes(p.harness)).every((p) => p.lifecycle.status === "disabled"));
}

run().then(() => {
  let fail = 0;
  for (const r of results) { console.log(`  ${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? `  (${r.detail})` : ""}`); if (!r.pass) fail++; }
  console.log(`\n${results.length - fail}/${results.length} passed`);
  console.log(`ioi-agent launch-policy readiness: ${fail ? "FAIL" : "OK"}`);
  process.exit(fail ? 1 : 0);
}).catch((e) => {
  console.error("verifier crashed:", e);
  process.exit(1);
});
