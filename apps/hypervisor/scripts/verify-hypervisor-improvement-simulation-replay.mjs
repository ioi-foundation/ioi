#!/usr/bin/env node
// Governed policy simulation / what-if replay done-bar.
//
// Proves operators can see what a proposed skill/policy/affinity change WOULD have done
// before approving it: deterministic counterfactual replay over recent real runs (same
// inputs → same report hash), derived-only and non-mutating (no durable record changes,
// no model/harness calls), privacy-safe (refs/counts/reason codes only — never private or
// secret bodies), honest governance flags (high-impact gating is a named CANDIDATE, not
// faked enforcement), saved reports receipted + ledger-indexed, and apply citing the
// latest simulation. Runs two REAL direct launches to seed replay subjects (≈30s).
// Usage: node apps/hypervisor/scripts/verify-hypervisor-improvement-simulation-replay.mjs

import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const { mintApprovalGrant } = await import(path.join(HERE, "../../../scripts/lib/mint-approval-grant.mjs"));

const DAEMON = (process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765").replace(/\/$/, "");
const SHELL = (process.env.IOI_HYPERVISOR_APP_URL || "http://127.0.0.1:4173").replace(/\/$/, "");

const results = [];
const ok = (name, cond, detail) => { results.push({ name, pass: !!cond, detail: detail || "" }); };
// node:http, not fetch: synchronous ioi-agent launches legitimately run longer than undici's
// fixed 300s headers timeout under host load (the 600s driver budget) — goalrun convention.
function jd(method, url, body) {
  const target = new URL(url.startsWith("http") ? url : `${DAEMON}${url}`);
  const payload = body ? JSON.stringify(body) : null;
  return new Promise((resolve, reject) => {
    const req = http.request(
      { hostname: target.hostname, port: target.port, path: target.pathname + target.search, method,
        headers: { "content-type": "application/json", ...(payload ? { "content-length": Buffer.byteLength(payload) } : {}) } },
      (res) => {
        let raw = "";
        res.on("data", (c) => { raw += c; });
        res.on("end", () => {
          let j = {};
          try { j = JSON.parse(raw); } catch { j = {}; }
          resolve({ status: res.statusCode, j });
        });
      },
    );
    req.on("error", reject);
    if (payload) req.write(payload);
    req.end();
  });
}
const launch = async (goal) => {
  const a = await jd("POST", "/v1/hypervisor/ioi-agent/launch", { goal, strategy: "direct" });
  const grant = mintApprovalGrant({ policyHash: a.j.approval.policy_hash, requestHash: a.j.approval.request_hash });
  return jd("POST", "/v1/hypervisor/ioi-agent/launch", { launch_id: a.j.launch_id, wallet_approval_grant: grant });
};
const simulate = async (id, body) => jd("POST", `/v1/hypervisor/intelligence/improvement-proposals/${id}/simulate`, body || {});
const proposalById = async (id) =>
  ((await jd("GET", "/v1/hypervisor/intelligence/improvement-proposals")).j?.proposals || []).find((p) => p.improvement_id === id) || {};
const snapshot = async (tag) => JSON.stringify([
  (await jd("GET", "/v1/hypervisor/ioi-agent/launch-policies")).j,
  (await jd("GET", `/v1/hypervisor/skill-entries?q=vfysim-${tag}`)).j,
  (await jd("GET", `/v1/hypervisor/automation-affinities?q=vfysim-${tag}`)).j,
]);

async function run() {
  const tag = Date.now().toString(16);
  const privMarker = `simpriv-${tag}`;
  const secretMarker = `simsecret-${tag}`;
  await jd("POST", "/v1/hypervisor/harness-profiles/hp_opencode/enable");
  const privEntry = (await jd("POST", "/v1/hypervisor/memory-entries", { title: `sim-priv-${tag}`, entry_kind: "fact", body: privMarker, sensitivity: "private" })).j?.record || {};
  const secretEntry = (await jd("POST", "/v1/hypervisor/memory-entries", { title: `sim-secret-${tag}`, entry_kind: "fact", body: secretMarker, sensitivity: "secret" })).j?.record || {};

  // ── Seed replay subjects: two REAL executed launches ──
  const l1 = await launch(`vfysim${tag} exercise the replay lane once`);
  const l2 = await launch(`vfysim${tag} exercise the replay lane again`);
  ok("two real launches executed as replay subjects", l1.status === 200 && l2.status === 200);

  // ── Proposals under test (one per overlay class) ──
  const mkProp = (payload) => jd("POST", "/v1/hypervisor/intelligence/improvement-proposals", payload);
  const skillProp = (await mkProp({
    proposal_kind: "skill_improvement", signal: "repeated_successful_goal_pattern",
    evidence_refs: [`ioi-agent-launch://vfysim-${tag}`],
    suggested: { title: `Skill vfysim-${tag}`, description: "replay-lane skill under simulation" },
  })).j?.proposal || {};
  const policyProp = (await mkProp({
    proposal_kind: "launch_policy_suggestion", signal: "repeated_harness_model_preference",
    evidence_refs: [`ioi-agent-launch://vfysim-${tag}`],
    suggested: { harness_preferences: { preferred_harness_refs: [], excluded_harness_refs: ["harness-profile:hp_opencode", "harness-profile:hp_deepseek_tui", "harness-profile:hp_codex", "harness-profile:hp_claude_code"], allow_fallback: false }, assurance: { require_compare: true } },
  })).j?.proposal || {};
  const affProp = (await mkProp({
    proposal_kind: "automation_readiness", signal: "repeated_successful_goal_pattern",
    evidence_refs: [`ioi-agent-launch://vfysim-${tag}`],
    suggested: { title: `Affinity vfysim-${tag}`, goal_pattern: `vfysim${tag}` },
  })).j?.proposal || {};
  ok("skill/policy/affinity proposals created pending",
    [skillProp, policyProp, affProp].every((p) => p.state === "pending" && p.improvement_id));

  const before = await snapshot(tag);
  const seedBefore = (await jd("GET", "/v1/hypervisor/ioi-agent/launch-policies/pol_fast_local")).j?.policy || {};

  // ── Policy what-if: kernel-recomputed launch replay with blocker deltas ──
  const sim1 = (await simulate(policyProp.improvement_id)).j?.report || {};
  const sim2 = (await simulate(policyProp.improvement_id)).j?.report || {};
  ok("simulation is declared deterministic, derived-only, and non-mutating",
    sim1.deterministic === true && sim1.derived_only === true && sim1.non_mutating === true
    && String(sim1.registry_posture || "").includes("recorded, not historical")
    && String(sim1.body_disclosure || "").includes("never appear"));
  ok("deterministic repeatability: same inputs produce the same report hash",
    String(sim1.report_hash || "").startsWith("sha256:") && sim1.report_hash === sim2.report_hash, sim1.report_hash);
  const mine = (sim1.scenarios || []).filter((s) => s.scenario_kind === "launch_replay" && String(s.goal_pattern || "").startsWith(`vfysim${tag}`));
  ok("launch replay covers the recent real launches", mine.length === 2
    && mine.every((s) => String(s.subject_ref || "").startsWith("ioi-agent-launch://") && (s.evidence_refs || []).length >= 1));
  ok("exclusion patch flips replayed selections (before ran, after blocked/rerouted)",
    mine.every((s) => s.changed === true && s.before.selected_harness_ref && (s.after.blocked_reason || s.after.selected_harness_ref !== s.before.selected_harness_ref)),
    JSON.stringify(mine[0]?.after || {}).slice(0, 120));
  ok("blocker deltas counted and summarized",
    (sim1.summary?.blockers_introduced || 0) >= 2 && sim1.summary?.scenarios >= 4 && sim1.summary?.changed >= 2,
    JSON.stringify(sim1.summary));
  const expectHigh = (sim1.summary?.changed || 0) >= 3 || (sim1.summary?.blockers_introduced || 0) > 0;
  ok("high-impact gating is named AND enforced (approval + release gate at apply time)",
    sim1.governance?.high_impact === expectHigh && sim1.governance?.high_impact === true
    && String(sim1.governance?.requirement || "").includes("approval-request") && sim1.governance?.enforced === true);

  // ── Skill what-if: projection replay shows the virtual skill without creating it ──
  const skillSim = (await simulate(skillProp.improvement_id)).j?.report || {};
  const projScenarios = (skillSim.scenarios || []).filter((s) => s.scenario_kind === "memory_projection_replay");
  ok("skill what-if replays memory projections with the virtual skill eligible",
    projScenarios.length >= 2 && projScenarios.some((s) => s.after?.simulated_skill_eligible === true && s.changed === true));

  // ── Affinity what-if: goal matching replay ──
  const affSim = (await simulate(affProp.improvement_id)).j?.report || {};
  const affScenarios = (affSim.scenarios || []).filter((s) => s.scenario_kind === "affinity_match_replay");
  ok("affinity what-if surfaces newly matching goals",
    affScenarios.length >= 2 && affScenarios.every((s) => s.changed === true && s.after?.automation_affinity_match === `Affinity vfysim-${tag}`));

  // ── Non-mutation + privacy ──
  const after = await snapshot(tag);
  const propAfterUnsaved = await proposalById(policyProp.improvement_id);
  ok("unsaved simulation mutates nothing (policies/skills/affinities identical, proposal unstamped)",
    before === after && propAfterUnsaved.state === "pending" && !propAfterUnsaved.latest_simulation_ref && !sim1.simulation_ref);
  const allReports = JSON.stringify([sim1, skillSim, affSim]);
  ok("reports carry refs/counts/reason codes only — no private or secret memory bodies",
    !allReports.includes(privMarker) && !allReports.includes(secretMarker));

  // ── Save: receipted report, retrievable, proposal stamped, seed untouched ──
  const saved = (await simulate(policyProp.improvement_id, { save: true })).j?.report || {};
  const simId = String(saved.simulation_ref || "").replace("simulation-report://", "");
  const fetched = (await jd("GET", `/v1/hypervisor/intelligence/simulation-reports/${simId}`)).j?.report || {};
  ok("saved report is receipted and retrievable with the same hash",
    simId.startsWith("sim_") && (saved.receipt_refs || []).some((r) => String(r).startsWith("receipt://hypervisor/simulation/"))
    && fetched.report_hash === saved.report_hash && saved.report_hash === sim1.report_hash);
  const stamped = await proposalById(policyProp.improvement_id);
  ok("proposal carries latest_simulation_ref + hash + high-impact flag",
    stamped.latest_simulation_ref === saved.simulation_ref && stamped.latest_simulation_hash === saved.report_hash && stamped.latest_simulation_high_impact === true);
  const seedAfter = (await jd("GET", "/v1/hypervisor/ioi-agent/launch-policies/pol_fast_local")).j?.policy || {};
  ok("protected seed policies untouched by simulation", JSON.stringify(seedAfter) === JSON.stringify(seedBefore) && seedAfter.protected === true);

  // ── Governance flow: simulate → approve → satisfy the (possibly high-impact) gate → apply ──
  await simulate(skillProp.improvement_id, { save: true });
  await jd("POST", `/v1/hypervisor/intelligence/improvement-proposals/${skillProp.improvement_id}/approve`);
  const skillGate = (await jd("POST", "/v1/hypervisor/governance/approval-requests", { subject_ref: skillProp.proposal_ref, request_kind: "improvement_apply", reason: "verifier gate" })).j?.approval_request || {};
  await jd("PATCH", `/v1/hypervisor/governance/approval-requests/${skillGate.id}`, { transition: "approve", reviewer_ref: "principal://verifier" });
  const skillRel = (await jd("POST", "/v1/hypervisor/governance/release-controls", { release_target_ref: skillProp.proposal_ref, reason: "verifier gate" })).j?.release_control || {};
  await jd("PATCH", `/v1/hypervisor/governance/release-controls/${skillRel.id}`, { transition: "open" });
  await jd("PATCH", `/v1/hypervisor/intelligence/improvement-proposals/${skillProp.improvement_id}`, { approval_request_ref: skillGate.ref, release_control_ref: skillRel.ref });
  const applied = (await jd("POST", `/v1/hypervisor/intelligence/improvement-proposals/${skillProp.improvement_id}/apply`)).j?.proposal || {};
  ok("apply cites the latest simulation (evidence suggests, simulation previews, governance decides)",
    applied.state === "applied" && String(applied.applied_ref || "").startsWith("skill-entry://")
    && String(applied.latest_simulation_ref || "").startsWith("simulation-report://"));

  // ── Ledger indexing ──
  const ledger = (await jd("GET", "/v1/hypervisor/work-ledger")).j?.entries || [];
  const ledgerEntry = ledger.find((e) => e.kind === "simulation_report" && e.simulation_ref === saved.simulation_ref);
  ok("Work Ledger indexes the saved simulation report",
    !!ledgerEntry && ledgerEntry.report_hash === saved.report_hash && ledgerEntry.proposal_ref === policyProp.proposal_ref && ledgerEntry.status === "high_impact");

  // ── UI: Simulate button → report page; card links the latest simulation ──
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1600, height: 1000 } });
  const consoleErrors = [];
  page.on("pageerror", (e) => consoleErrors.push(String(e)));
  await page.goto(`${SHELL}/__ioi/agent-studio#launch-policies`, { waitUntil: "networkidle" });
  await page.waitForSelector("#improvement-proposals", { timeout: 15000 });
  const simForm = `form[action="/__ioi/agent-studio/improvements/${affProp.improvement_id}/simulate"] button`;
  ok("pending proposal card offers Simulate impact", await page.locator(simForm).count() === 1);
  await Promise.all([page.waitForURL("**/__ioi/intelligence/simulations/**", { timeout: 15000 }), page.click(simForm)]);
  const pageText = await page.evaluate(() => document.body.innerText);
  ok("simulation report page renders scenarios, hash, and before/after deltas",
    /what-if simulation/i.test(pageText) && /deterministic/i.test(pageText) && /sha256:/i.test(pageText)
    && /affinity_match_replay/i.test(pageText) && /launch_replay/i.test(pageText) && /blockers removed/i.test(pageText));
  ok("report page leaks no private or secret bodies", !pageText.includes(privMarker) && !pageText.includes(secretMarker));
  await page.goto(`${SHELL}/__ioi/agent-studio#launch-policies`, { waitUntil: "networkidle" });
  const cardLink = await page.locator(`a[href^="/__ioi/intelligence/simulations/"]`).count();
  const highImpactCard = await page.locator(`a[href="/__ioi/intelligence/simulations/${simId}"]`).textContent().catch(() => "");
  ok("proposal cards link their latest simulation (high-impact marked)",
    cardLink >= 2 && /high impact/i.test(highImpactCard || ""));
  await page.goto(`${SHELL}/__ioi/work-ledger`, { waitUntil: "networkidle" });
  await page.click(`text=Simulations`);
  await page.waitForSelector(".wlrow", { timeout: 15000 });
  await page.locator(".wlrow").first().click();
  await page.waitForSelector(`#wl-drawer a[href^="/__ioi/intelligence/simulations/"]`, { timeout: 15000 });
  ok("Work Ledger UI filters simulations and backlinks the report page", true);
  ok("no console errors", consoleErrors.length === 0, consoleErrors.slice(0, 2).join(" | "));
  await browser.close();
  const ft = await fetch(`${SHELL}/__ioi/fallthrough`).then((r) => r.json()).catch(() => ({}));
  ok("fallthrough stays empty", Array.isArray(ft.proxied) && ft.proxied.length === 0);

  // ── Cleanup + posture restore ──
  await jd("POST", `/v1/hypervisor/intelligence/improvement-proposals/${policyProp.improvement_id}/reject`, { reason: "verifier fixture" });
  await jd("POST", `/v1/hypervisor/intelligence/improvement-proposals/${affProp.improvement_id}/reject`, { reason: "verifier fixture" });
  await jd("PATCH", `/v1/hypervisor/skill-entries/${String(applied.applied_ref || "").replace("skill-entry://", "")}`, { status: "archived" });
  await jd("PATCH", `/v1/hypervisor/memory-entries/${privEntry.entry_id}`, { status: "archived" });
  await jd("PATCH", `/v1/hypervisor/memory-entries/${secretEntry.entry_id}`, { status: "archived" });
  await jd("DELETE", `/v1/hypervisor/governance/approval-requests/${skillGate.id}`);
  await jd("DELETE", `/v1/hypervisor/governance/release-controls/${skillRel.id}`);
  await jd("POST", "/v1/hypervisor/harness-profiles/hp_opencode/disable");
  const fin = await jd("GET", "/v1/hypervisor/harness-profiles");
  ok("fixtures cleaned + drivers restored",
    (fin.j?.profiles || []).filter((p) => p.harness === "opencode").every((p) => p.lifecycle.status === "disabled"));
}

run().then(() => {
  let fail = 0;
  for (const r of results) { console.log(`  ${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? `  (${r.detail})` : ""}`); if (!r.pass) fail++; }
  console.log(`\n${results.length - fail}/${results.length} passed`);
  console.log(`improvement simulation replay readiness: ${fail ? "FAIL" : "OK"}`);
  process.exit(fail ? 1 : 0);
}).catch((e) => {
  console.error("verifier crashed:", e);
  process.exit(1);
});
