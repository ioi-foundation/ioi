#!/usr/bin/env node
// Canary release + rollback done-bar.
//
// Proves a high-impact learned launch-policy change can be released to a BOUNDED audience
// before full rollout, then promoted or rolled back with receipts: a canary/cohort
// ReleaseControl makes apply create a rollout-bound VARIANT (base policy never replaced,
// protected seed untouched); launch preview/launch silently upgrades ONLY eligible contexts
// to the variant (explained with reason codes); closing the gate or rolling back restores
// base behavior everywhere without deleting any proposal/simulation/approval/release
// evidence; promote makes the variant normal behavior for every context. Runs two REAL
// direct launches to seed replay subjects and one REAL launch under the promoted overlay.
// Usage: node apps/hypervisor/scripts/verify-hypervisor-policy-canary-rollback.mjs

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
const launch = async (body) => {
  const a = await jd("POST", "/v1/hypervisor/ioi-agent/launch", body);
  if (a.status !== 403) return a;
  const grant = mintApprovalGrant({ policyHash: a.j.approval.policy_hash, requestHash: a.j.approval.request_hash });
  return jd("POST", "/v1/hypervisor/ioi-agent/launch", { launch_id: a.j.launch_id, wallet_approval_grant: grant });
};
const preview = async (extra) => (await jd("POST", "/v1/hypervisor/ioi-agent/launch-preview", {
  goal: "rollout probe goal for the canary lane", strategy: "direct",
  policy_ref: "ioi-agent-policy://pol_fast_local", ...extra,
})).j;

async function run() {
  const tag = Date.now().toString(16);
  const BASE = "ioi-agent-policy://pol_fast_local";
  // Rollout context now derives from DAEMON-KNOWN truth: the cohort member must be a real project.
  await jd("POST", "/v1/hypervisor/projects", { project_name: `vfycrb-${tag}`, repository_url: `https://github.com/ioi-foundation/vfycrb-${tag}` });
  const projRecords = (await jd("GET", "/v1/hypervisor/projects")).j;
  const projectId = ((projRecords.records || projRecords.projects || []).find((x) => String(x.project_id || "").includes(`vfycrb-${tag}`)) || {}).project_id || "";
  const cohortRef = `project://${projectId}`;
  await jd("POST", "/v1/hypervisor/harness-profiles/hp_opencode/enable");
  const l1 = await launch({ goal: `vfycrb${tag} exercise the rollout lane once`, strategy: "direct" });
  const l2 = await launch({ goal: `vfycrb${tag} exercise the rollout lane again`, strategy: "direct" });
  ok("two real launches executed as replay subjects", l1.status === 200 && l2.status === 200);
  const seedBefore = (await jd("GET", "/v1/hypervisor/ioi-agent/launch-policies/pol_fast_local")).j?.policy || {};

  // ── High-impact learned suggestion (benign: LOOSENS the private-local base to standard,
  // so every replayed launch flips posture — big, visible, but nothing blocks) ──
  const marker = `crb-learned-${tag}`;
  const prop = (await jd("POST", "/v1/hypervisor/intelligence/improvement-proposals", {
    proposal_kind: "launch_policy_suggestion", signal: "repeated_harness_model_preference",
    target_ref: BASE, evidence_refs: [`ioi-agent-launch://vfycrb-${tag}`],
    suggested: { description: marker, privacy: { local_only: false, forbid_remote_trust: false, forbid_provider_credentials: false } },
  })).j?.proposal || {};
  const sim = (await jd("POST", `/v1/hypervisor/intelligence/improvement-proposals/${prop.improvement_id}/simulate`, { save: true })).j?.report || {};
  ok("learned suggestion simulates high-impact (gate engages)", sim.governance?.high_impact === true, JSON.stringify(sim.summary));
  await jd("POST", `/v1/hypervisor/intelligence/improvement-proposals/${prop.improvement_id}/approve`);

  // ── Cohort-scoped ReleaseControl (rollout fields are durable governance truth) ──
  const appr = (await jd("POST", "/v1/hypervisor/governance/approval-requests", { subject_ref: prop.proposal_ref, request_kind: "improvement_apply", reason: `vfycrb-${tag}` })).j?.approval_request || {};
  await jd("PATCH", `/v1/hypervisor/governance/approval-requests/${appr.id}`, { transition: "approve", reviewer_ref: "principal://verifier" });
  const relResp = await jd("POST", "/v1/hypervisor/governance/release-controls", { release_target_ref: prop.proposal_ref, rollout_mode: "cohort", cohort_refs: [cohortRef], reason: `vfycrb-${tag}` });
  const rel = relResp.j?.release_control || {};
  const badMode = await jd("POST", "/v1/hypervisor/governance/release-controls", { release_target_ref: prop.proposal_ref, rollout_mode: "percentage" });
  const noPercent = await jd("POST", "/v1/hypervisor/governance/release-controls", { release_target_ref: prop.proposal_ref, rollout_mode: "canary" });
  ok("ReleaseControl carries validated rollout semantics (mode, cohort_refs, rollback_state)",
    rel.rollout_mode === "cohort" && JSON.stringify(rel.cohort_refs) === JSON.stringify([cohortRef])
    && rel.rollback_state === null && rel.promoted_at === null
    && badMode.j?.error?.code === "governance_rollout_mode_invalid" && noPercent.j?.error?.code === "governance_canary_percent_required");
  await jd("PATCH", `/v1/hypervisor/governance/release-controls/${rel.id}`, { transition: "open" });
  await jd("PATCH", `/v1/hypervisor/intelligence/improvement-proposals/${prop.improvement_id}`, { approval_request_ref: appr.ref, release_control_ref: rel.ref });

  // ── Apply under cohort scope → rollout-bound VARIANT, base untouched ──
  const applied = (await jd("POST", `/v1/hypervisor/intelligence/improvement-proposals/${prop.improvement_id}/apply`)).j?.proposal || {};
  const variantRef = String(applied.applied_ref || "");
  const variantId = variantRef.replace("ioi-agent-policy://", "");
  const variant = (await jd("GET", `/v1/hypervisor/ioi-agent/launch-policies/${variantId}`)).j?.policy || {};
  ok("apply creates a rollout-bound learned variant carrying full provenance",
    applied.state === "applied" && variant.rollout?.mode === "cohort" && variant.rollout?.state === "active"
    && variant.rollout?.base_policy_ref === BASE && variant.rollout?.release_control_ref === rel.ref
    && variant.rollout?.proposal_ref === prop.proposal_ref && String(variant.rollout?.simulation_ref || "").startsWith("simulation-report://")
    && String(variant.display_name || "").includes("cohort rollout"));
  const seedAfter = (await jd("GET", "/v1/hypervisor/ioi-agent/launch-policies/pol_fast_local")).j?.policy || {};
  ok("protected seed base policy is NOT mutated",
    JSON.stringify(seedAfter) === JSON.stringify(seedBefore) && seedAfter.protected === true && !JSON.stringify(seedAfter).includes(marker));

  // ── Scoped selection: only the cohort sees the learned policy ──
  const elig = await preview({ project_ref: projectId });
  ok("eligible cohort context is upgraded to the variant with an explained reason",
    elig.policy_ref === variantRef && String(elig.policy_rollout?.reason_code || "").startsWith("rollout_cohort_match")
    && elig.policy_rollout?.base_policy_ref === BASE && elig.privacy_posture !== "private_local");
  const inel = await preview({ project_ref: "project://prj_someone_else" });
  const anon = await preview({});
  ok("ineligible and anonymous contexts keep the base policy (still private-local)",
    inel.policy_ref === BASE && inel.policy_rollout === null && inel.privacy_posture === "private_local"
    && anon.policy_ref === BASE && anon.policy_rollout === null);

  // ── Canary bucketing is deterministic (100% hits, 0% misses) ──
  await jd("PATCH", `/v1/hypervisor/governance/release-controls/${rel.id}`, { rollout_mode: "canary", canary_percent: 100 });
  const canaryIn = await preview({});
  await jd("PATCH", `/v1/hypervisor/governance/release-controls/${rel.id}`, { canary_percent: 0 });
  const canaryOut = await preview({});
  ok("canary_percent bounds the audience deterministically (100% in, 0% out)",
    canaryIn.policy_ref === variantRef && String(canaryIn.policy_rollout?.reason_code || "").startsWith("rollout_canary_bucket")
    && canaryOut.policy_ref === BASE && canaryOut.policy_rollout === null);
  await jd("PATCH", `/v1/hypervisor/governance/release-controls/${rel.id}`, { rollout_mode: "cohort" });

  // ── The ReleaseControl stays the LIVE gate: closing it switches everyone back to base ──
  await jd("PATCH", `/v1/hypervisor/governance/release-controls/${rel.id}`, { transition: "close" });
  const gateClosed = await preview({ project_ref: projectId });
  await jd("PATCH", `/v1/hypervisor/governance/release-controls/${rel.id}`, { transition: "open" });
  ok("closing the release gate disables the overlay even for the cohort",
    gateClosed.policy_ref === BASE && gateClosed.policy_rollout === null);

  // ── UI: variant card badges + promote via Agent Studio; modal explains the overlay ──
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1600, height: 1000 } });
  const consoleErrors = [];
  page.on("pageerror", (e) => consoleErrors.push(String(e)));
  page.on("dialog", (d) => d.accept());
  await page.goto(`${SHELL}/__ioi/agent-studio#launch-policies`, { waitUntil: "networkidle" });
  const card = page.locator(`.lpcard[data-policy="${variantId}"]`);
  ok("Agent Studio shows the learned variant with rollout badges + promote/rollback",
    /cohort rollout · active/i.test(await card.innerText()) && /learned/i.test(await card.innerText())
    && await card.locator(`form[action*="/rollout/promote"] button`).count() === 1
    && await card.locator(`form[action*="/rollout/rollback"] button`).count() === 1);
  await Promise.all([page.waitForURL("**/agent-studio**"), card.locator(`form[action*="/rollout/promote"] button`).click()]);
  const promoted = (await jd("GET", `/v1/hypervisor/ioi-agent/launch-policies/${variantId}`)).j?.policy || {};
  const relPromoted = (await jd("GET", `/v1/hypervisor/governance/release-controls/${rel.id}`)).j?.release_control || {};
  ok("UI promote lands: variant promoted, ReleaseControl flipped to full with promoted_at",
    promoted.rollout?.state === "promoted" && !!promoted.rollout?.promoted_at
    && relPromoted.rollout_mode === "full" && !!relPromoted.promoted_at);
  const everyone = await preview({ project_ref: "project://prj_someone_else" });
  ok("after promote EVERY context sees the learned policy",
    everyone.policy_ref === variantRef && everyone.policy_rollout?.reason_code === "rollout_promoted_full");

  // New Session modal: select the base policy → preview explains the promoted overlay.
  await page.goto(`${SHELL}/`, { waitUntil: "networkidle" });
  await page.click('[data-testid="create-session-button"]');
  await page.waitForSelector("#ioi-ns-modal.open", { timeout: 15000 });
  await page.waitForSelector("#ioi-ns-policy", { timeout: 15000 });
  await page.selectOption("#ioi-ns-policy", BASE);
  await page.fill("#ioi-ns-goal", "probe the rollout overlay from the modal");
  await page.waitForFunction(() => /rollout/i.test(document.getElementById("ioi-ns-preview")?.innerText || ""), { timeout: 15000 });
  const modalPreview = await page.locator("#ioi-ns-preview").innerText();
  ok("New Session preview names the overlay, the variant, and why",
    /Rollout/i.test(modalPreview) && modalPreview.includes(variantId) && /rollout_promoted_full/.test(modalPreview) && /pol_fast_local/.test(modalPreview));
  await page.keyboard.press("Escape");

  // ── One REAL launch under the promoted overlay: runtime, not just preview ──
  const l3 = await launch({ goal: `vfycrb${tag} run under the promoted learned policy`, strategy: "direct", policy_ref: BASE });
  const launches = (await jd("GET", "/v1/hypervisor/ioi-agent/launches")).j?.launches || [];
  const l3rec = launches.find((l) => String(l.goal || "").includes("run under the promoted learned policy")) || {};
  ok("a real launch records the overlay: variant policy + rollout explanation on the launch record",
    l3.status === 200 && l3rec.policy_ref === variantRef && l3rec.policy_rollout?.reason_code === "rollout_promoted_full"
    && l3rec.policy_rollout?.release_control_ref === rel.ref);

  // ── Rollback via the UI: base behavior everywhere, evidence retained ──
  await page.goto(`${SHELL}/__ioi/agent-studio#launch-policies`, { waitUntil: "networkidle" });
  await Promise.all([page.waitForURL("**/agent-studio**"), page.locator(`.lpcard[data-policy="${variantId}"] form[action*="/rollout/rollback"] button`).click()]);
  const rolledBack = (await jd("GET", `/v1/hypervisor/ioi-agent/launch-policies/${variantId}`)).j?.policy || {};
  const relRolled = (await jd("GET", `/v1/hypervisor/governance/release-controls/${rel.id}`)).j?.release_control || {};
  ok("rollback disables the overlay: variant rolled_back + disabled, ReleaseControl records it",
    rolledBack.rollout?.state === "rolled_back" && !!rolledBack.rollout?.rolled_back_at && rolledBack.status === "disabled"
    && relRolled.rollback_state === "rolled_back" && !!relRolled.rolled_back_at);
  const backToBase = await preview({ project_ref: projectId });
  const explicitVariant = await jd("POST", "/v1/hypervisor/ioi-agent/launch-preview", { goal: "explicit variant probe", policy_ref: variantRef });
  ok("all contexts return to base; explicit selection of the rolled-back variant fails closed",
    backToBase.policy_ref === BASE && backToBase.policy_rollout === null
    && explicitVariant.status === 409 && explicitVariant.j?.error?.code === "ioi_agent_policy_disabled");
  const evidence = [
    (await jd("GET", `/v1/hypervisor/intelligence/improvement-proposals/${prop.improvement_id}`)).j?.proposal,
    (await jd("GET", `/v1/hypervisor/intelligence/simulation-reports/${String(applied.latest_simulation_ref || "").replace("simulation-report://", "")}`)).j?.report,
    (await jd("GET", `/v1/hypervisor/governance/approval-requests/${appr.id}`)).j?.approval_request,
    relRolled, rolledBack,
  ];
  ok("rollback deletes NO evidence: proposal, simulation, approval, release, and variant all retained",
    evidence.every(Boolean) && evidence[0].state === "applied");

  // ── Receipts + Work Ledger: apply, promote, rollback — full chain cited ──
  const ledger = (await jd("GET", "/v1/hypervisor/work-ledger")).j?.entries || [];
  const applyEntry = ledger.find((e) => e.kind === "improvement_applied" && e.proposal_ref === prop.proposal_ref);
  const promoteEntry = ledger.find((e) => e.kind === "policy_rollout" && e.status === "promote" && e.policy_ref === variantRef);
  const rollbackEntry = ledger.find((e) => e.kind === "policy_rollout" && e.status === "rollback" && e.policy_ref === variantRef);
  ok("Work Ledger shows apply + promote + rollback citing proposal/simulation/approval/release",
    !!applyEntry && applyEntry.approval_request_ref === appr.ref && applyEntry.release_control_ref === rel.ref
    && [promoteEntry, rollbackEntry].every((e) => !!e && e.base_policy_ref === BASE && e.proposal_ref === prop.proposal_ref
      && e.approval_request_ref === appr.ref && e.release_control_ref === rel.ref
      && String(e.simulation_ref || "").startsWith("simulation-report://")));
  await page.goto(`${SHELL}/__ioi/work-ledger`, { waitUntil: "networkidle" });
  await page.click("text=Rollouts");
  await page.waitForSelector(".wlrow", { timeout: 15000 });
  await page.locator(".wlrow").first().click();
  const drawer = await page.locator("#wl-drawer").innerText();
  ok("ledger drawer backlinks the learned + base policies and the governance chain",
    /Learned policy/i.test(drawer) && /Base policy/i.test(drawer) && drawer.includes("approval-request://") && drawer.includes("release-control://"));
  ok("no console errors", consoleErrors.length === 0, consoleErrors.slice(0, 2).join(" | "));
  await browser.close();
  const ft = await fetch(`${SHELL}/__ioi/fallthrough`).then((r) => r.json()).catch(() => ({}));
  ok("fallthrough stays empty", Array.isArray(ft.proxied) && ft.proxied.length === 0);

  // ── Cleanup + posture restore (evidence receipts remain by design) ──
  await jd("DELETE", `/v1/hypervisor/ioi-agent/launch-policies/${variantId}`);
  await jd("DELETE", `/v1/hypervisor/governance/approval-requests/${appr.id}`);
  await jd("DELETE", `/v1/hypervisor/governance/release-controls/${rel.id}`);
  await jd("POST", "/v1/hypervisor/harness-profiles/hp_opencode/disable");
  const fin = await jd("GET", "/v1/hypervisor/harness-profiles");
  ok("fixtures cleaned + drivers restored",
    (fin.j?.profiles || []).filter((p) => p.harness === "opencode").every((p) => p.lifecycle.status === "disabled"));
}

run().then(() => {
  let fail = 0;
  for (const r of results) { console.log(`  ${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? `  (${r.detail})` : ""}`); if (!r.pass) fail++; }
  console.log(`\n${results.length - fail}/${results.length} passed`);
  console.log(`policy canary rollback readiness: ${fail ? "FAIL" : "OK"}`);
  process.exit(fail ? 1 : 0);
}).catch((e) => {
  console.error("verifier crashed:", e);
  process.exit(1);
});
