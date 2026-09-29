#!/usr/bin/env node
// Governed policy simulation / what-if replay done-bar.
//
// Proves operators can see what a proposed skill or affinity change WOULD have done before
// approving it: deterministic counterfactual replay over recent real records (same inputs → same
// report hash), derived-only and non-mutating (no durable record changes, no model/harness calls),
// privacy-safe (refs/counts/reason codes only — never private or secret bodies), honest governance
// flags (high-impact gating named AND enforced), saved reports receipted + ledger-indexed, and apply
// citing the latest simulation.
// GOV-ATTR-1: the gate ApprovalRequest in the governance flow is DECIDED by a real authenticated
// principal — the request body names no reviewer, and the record must report that session's
// server-derived `user://<principal_id>`. Canon: `identity-access-and-metering.md`.
//
// RE-TYPED 2026-09-29 (R-240, GoalRun residue). Its replay subjects were two REAL IOI Agent launches,
// and its policy what-if replayed their execution-strategy selection (direct versus goal_run) under a
// learned launch-policy patch. R-192 (S5-1) took goal pursuit out of the Hypervisor — a goal run is
// an ioi.ai composition over the thread orchestration primitives (standing owner ruling 2026-09-24) —
// so the launch lane is gone, strategy selection answers `goal_pursuit_retired_from_platform`, and
// the verifier crashed on its first launch. The replay subjects are now receipted memory projections
// (the record the simulation's projection replay reads); the determinism, non-mutation, save,
// high-impact and governance claims ride the skill what-if; the launch-replay, blocker-delta,
// affinity-match (it matched only launch goals) and protected-seed clauses are dropped.
//
// RE-AIMED 2026-09-29 (R-240, launcher leftovers): the daemon retired the launch and affinity-match
// replays outright (they read `ioi-agent-launches` records, which nothing writes) and every report now
// NAMES them in `retired_scenario_kinds` with a typed reason, with no blocker deltas it cannot measure;
// the report page says so. A launch-policy suggestion is refused at propose and at simulate.
//
// Usage: node apps/hypervisor/scripts/verify-hypervisor-improvement-simulation-replay.mjs  (≈1 min)
// Its own isolated daemon + serve, the operator signed in (lib/verifier-stack.mjs); an explicit
// URL naming the owner's stack (:8765, :36173, :4173) is refused.

import { chromium } from "playwright";
import { ANONYMOUS, verifierStack } from "./lib/verifier-stack.mjs";

const STACK = await verifierStack({ serve: true });
const DAEMON = STACK.daemonUrl;
const SHELL = STACK.serveUrl;

const results = [];
const ok = (name, cond, detail) => { results.push({ name, pass: !!cond, detail: detail || "" }); };
// Every request carries the stack operator's session (verifier-stack) unless it names its own
// `authorization` (the reviewer) or opts out with ANONYMOUS (the reviewer's own login).
async function jd(method, url, body, headers) {
  const r = await fetch(url.startsWith("http") ? url : `${DAEMON}${url}`, {
    method,
    headers: { "content-type": "application/json", ...(headers || {}) },
    body: body ? JSON.stringify(body) : undefined,
  }).catch(() => null);
  const text = r ? await r.text().catch(() => "") : "";
  let j = {}; try { j = JSON.parse(text); } catch { j = {}; }
  return { status: r?.status ?? 0, j };
}
// GOV-ATTR-1 — a governance decision's reviewer is WHO DECIDED. Canon
// (`identity-access-and-metering.md`): "Request bodies never select the acting principal." So the
// gate approval below is approved BY a real principal: provisioned through the operator session,
// logged in for itself, and asked via `whoami` who it is — the expected reviewer ref is the
// daemon's own answer, never a value assembled here. Admission is load-bearing: an unadmitted
// fixture would approve anonymously and prove nothing about the identity seam, so it fails the
// verifier outright.
async function admitReviewer(tag) {
  const operator = { authorization: `Bearer ${STACK.token}` };
  const principalId = `usr_vfysim${tag}`;
  const email = `vfysim-${tag}@local`;
  const password = `vfysim-${tag}-reviewer-pass`;
  const created = await jd("POST", "/v1/hypervisor/principals", { email, password, principal_id: principalId }, operator);
  const login = (await jd("POST", "/v1/hypervisor/auth/login", { email, password }, { [ANONYMOUS]: "1" })).j || {};
  const token = login.session_token || "";
  const session = { authorization: `Bearer ${token}` };
  const who = token ? (await jd("GET", "/v1/hypervisor/auth/whoami", undefined, session)).j || {} : {};
  const derived = who.authenticated === true ? String(who.principal?.principal_id || "") : "";
  if (!derived) throw new Error(`reviewer identity fixture NOT admitted (create ${created.status}, whoami ${JSON.stringify(who).slice(0, 200)}) — the gate approval cannot cross the real identity seam`);
  return { principalId: derived, ref: `user://${derived}`, headers: session, operator };
}
const simulate = async (id, body) => jd("POST", `/v1/hypervisor/intelligence/improvement-proposals/${id}/simulate`, body || {});
const proposalById = async (id) =>
  ((await jd("GET", "/v1/hypervisor/intelligence/improvement-proposals")).j?.proposals || []).find((p) => p.improvement_id === id) || {};
const snapshot = async (tag) => JSON.stringify([
  (await jd("GET", `/v1/hypervisor/skill-entries?q=vfysim-${tag}`)).j,
  (await jd("GET", `/v1/hypervisor/automation-affinities?q=vfysim-${tag}`)).j,
  (await jd("GET", "/v1/hypervisor/memory-projections")).j,
]);

async function run() {
  const tag = Date.now().toString(16);
  const privMarker = `simpriv-${tag}`;
  const secretMarker = `simsecret-${tag}`;
  const reviewer = await admitReviewer(tag);
  ok("real principal + login session admitted as the deciding identity", !!reviewer.ref, reviewer.ref);
  const privEntry = (await jd("POST", "/v1/hypervisor/memory-entries", { title: `sim-priv-${tag}`, entry_kind: "fact", body: privMarker, sensitivity: "private" })).j?.record || {};
  const secretEntry = (await jd("POST", "/v1/hypervisor/memory-entries", { title: `sim-secret-${tag}`, entry_kind: "fact", body: secretMarker, sensitivity: "secret" })).j?.record || {};

  // ── Seed replay subjects: three receipted memory projections (R-240, 2026-09-29: two REAL IOI
  // Agent launches stood here; that lane is retired) ──
  const subjects = [];
  for (const harness of ["harness-profile:hp_opencode", "harness-profile:hp_deepseek_tui", "harness-profile:hp_codex"]) {
    const p = (await jd("POST", "/v1/hypervisor/memory-projections", { harness_profile_ref: harness, session_ref: `session://vfysim-${tag}`, goal: `vfysim${tag} exercise the replay lane` })).j?.projection || {};
    if (p.projection_ref) subjects.push(p.projection_ref);
  }
  ok("three receipted memory projections recorded as replay subjects", subjects.length === 3, subjects.join(","));

  // ── Proposals under test (one per overlay class the platform still replays) ──
  const mkProp = (payload) => jd("POST", "/v1/hypervisor/intelligence/improvement-proposals", payload);
  const skillProp = (await mkProp({
    proposal_kind: "skill_improvement", signal: "repeated_successful_goal_pattern",
    evidence_refs: subjects,
    suggested: { title: `Skill vfysim-${tag}`, description: "replay-lane skill under simulation" },
  })).j?.proposal || {};
  const affProp = (await mkProp({
    proposal_kind: "automation_readiness", signal: "repeated_successful_goal_pattern",
    evidence_refs: subjects,
    suggested: { title: `Affinity vfysim-${tag}`, goal_pattern: `vfysim${tag}` },
  })).j?.proposal || {};
  ok("skill/affinity proposals created pending", [skillProp, affProp].every((p) => p.state === "pending" && p.improvement_id));

  const before = await snapshot(tag);

  // ── Skill what-if: projection replay shows the virtual skill without creating it ──
  const sim1 = (await simulate(skillProp.improvement_id)).j?.report || {};
  const sim2 = (await simulate(skillProp.improvement_id)).j?.report || {};
  ok("simulation is declared deterministic, derived-only, and non-mutating",
    sim1.deterministic === true && sim1.derived_only === true && sim1.non_mutating === true
    && String(sim1.registry_posture || "").includes("recorded, not historical")
    && String(sim1.body_disclosure || "").includes("never appear"));
  ok("deterministic repeatability: same inputs produce the same report hash",
    String(sim1.report_hash || "").startsWith("sha256:") && sim1.report_hash === sim2.report_hash, sim1.report_hash);
  const projScenarios = (sim1.scenarios || []).filter((s) => s.scenario_kind === "memory_projection_replay" && subjects.includes(s.subject_ref));
  ok("skill what-if replays memory projections with the virtual skill eligible",
    projScenarios.length >= 2 && projScenarios.some((s) => s.after?.simulated_skill_eligible === true && s.changed === true),
    `${projScenarios.length} of this run's subjects replayed`);
  ok("changes are counted and summarized", sim1.summary?.scenarios >= 3 && sim1.summary?.changed >= 3, JSON.stringify(sim1.summary));
  const expectHigh = (sim1.summary?.changed || 0) >= 3;
  ok("high-impact gating is named AND enforced (approval + release gate at apply time)",
    sim1.governance?.high_impact === expectHigh && sim1.governance?.high_impact === true
    && String(sim1.governance?.requirement || "").includes("approval-request") && sim1.governance?.enforced === true);
  // R-240 (2026-09-29): "launch replay covers the recent real launches", "exclusion patch flips
  // replayed selections", "blocker deltas counted" and "affinity what-if surfaces newly matching
  // goals" all replayed IOI Agent launch records — the retired lane — and are dropped. The report
  // names those replays retired instead of reporting zero of them (R-240, launcher leftovers).
  ok("the report names the launch and affinity-match replays RETIRED (typed reason), replays none of them, and claims no blocker deltas",
    JSON.stringify((sim1.retired_scenario_kinds || []).map((k) => `${k.scenario_kind}:${k.reason_code}`)) === JSON.stringify(["launch_replay:ioi_agent_launch_retired", "affinity_match_replay:ioi_agent_launch_retired"])
    && (sim1.scenarios || []).every((sc) => sc.scenario_kind === "memory_projection_replay")
    && !("blockers_introduced" in (sim1.summary || {})),
    JSON.stringify(sim1.retired_scenario_kinds || []));
  const affSim = (await simulate(affProp.improvement_id)).j?.report || {};

  // ── Non-mutation + privacy ──
  const after = await snapshot(tag);
  const propAfterUnsaved = await proposalById(skillProp.improvement_id);
  ok("unsaved simulation mutates nothing (skills/affinities/projections identical, proposal unstamped)",
    before === after && propAfterUnsaved.state === "pending" && !propAfterUnsaved.latest_simulation_ref && !sim1.simulation_ref);
  const allReports = JSON.stringify([sim1, affSim]);
  ok("reports carry refs/counts/reason codes only — no private or secret memory bodies",
    !allReports.includes(privMarker) && !allReports.includes(secretMarker));

  // ── Save: receipted report, retrievable, proposal stamped ──
  const saved = (await simulate(skillProp.improvement_id, { save: true })).j?.report || {};
  const simId = String(saved.simulation_ref || "").replace("simulation-report://", "");
  const fetched = (await jd("GET", `/v1/hypervisor/intelligence/simulation-reports/${simId}`)).j?.report || {};
  ok("saved report is receipted and retrievable with the same hash",
    simId.startsWith("sim_") && (saved.receipt_refs || []).some((r) => String(r).startsWith("receipt://hypervisor/simulation/"))
    && fetched.report_hash === saved.report_hash && saved.report_hash === sim1.report_hash);
  const stamped = await proposalById(skillProp.improvement_id);
  ok("proposal carries latest_simulation_ref + hash + high-impact flag",
    stamped.latest_simulation_ref === saved.simulation_ref && stamped.latest_simulation_hash === saved.report_hash && stamped.latest_simulation_high_impact === true);

  // ── Governance flow: simulate → approve → satisfy the high-impact gate → apply ──
  await jd("POST", `/v1/hypervisor/intelligence/improvement-proposals/${skillProp.improvement_id}/approve`);
  const skillGate = (await jd("POST", "/v1/hypervisor/governance/approval-requests", { subject_ref: skillProp.proposal_ref, request_kind: "improvement_apply", reason: "verifier gate" })).j?.approval_request || {};
  // The approval is DECIDED by the admitted reviewer session; the body names nobody (GOV-ATTR-1).
  await jd("PATCH", `/v1/hypervisor/governance/approval-requests/${skillGate.id}`, { transition: "approve" }, reviewer.headers);
  const skillGateDecided = (await jd("GET", `/v1/hypervisor/governance/approval-requests/${skillGate.id}`)).j?.approval_request || {};
  ok("the gate approval is attributed to the SERVER-DERIVED principal of the deciding session",
    skillGateDecided.status === "approved" && skillGateDecided.reviewer_ref === reviewer.ref,
    `reviewer ${skillGateDecided.reviewer_ref} · expected ${reviewer.ref}`);
  const skillRel = (await jd("POST", "/v1/hypervisor/governance/release-controls", { release_target_ref: skillProp.proposal_ref, reason: "verifier gate" })).j?.release_control || {};
  await jd("PATCH", `/v1/hypervisor/governance/release-controls/${skillRel.id}`, { transition: "open" });
  await jd("PATCH", `/v1/hypervisor/intelligence/improvement-proposals/${skillProp.improvement_id}`, { approval_request_ref: skillGate.ref, release_control_ref: skillRel.ref });
  const applied = (await jd("POST", `/v1/hypervisor/intelligence/improvement-proposals/${skillProp.improvement_id}/apply`)).j?.proposal || {};
  ok("apply cites the latest simulation (evidence suggests, simulation previews, governance decides)",
    applied.state === "applied" && String(applied.applied_ref || "").startsWith("skill-entry://")
    && applied.latest_simulation_ref === saved.simulation_ref);

  // ── Ledger indexing ──
  const ledger = (await jd("GET", "/v1/hypervisor/work-ledger")).j?.entries || [];
  const ledgerEntry = ledger.find((e) => e.kind === "simulation_report" && e.simulation_ref === saved.simulation_ref);
  ok("Work Ledger indexes the saved simulation report",
    !!ledgerEntry && ledgerEntry.report_hash === saved.report_hash && ledgerEntry.proposal_ref === skillProp.proposal_ref && ledgerEntry.status === "high_impact");

  // ── UI: Simulate button → report page; card links the latest simulation ──
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1600, height: 1000 } });
  await STACK.signIn(page);
  const consoleErrors = [];
  page.on("pageerror", (e) => consoleErrors.push(String(e)));
  await page.goto(`${SHELL}/__ioi/agent-studio#improvements`, { waitUntil: "networkidle" });
  await page.waitForSelector("#improvement-proposals", { timeout: 15000 });
  const simForm = `form[action="/__ioi/agent-studio/improvements/${affProp.improvement_id}/simulate"] button`;
  ok("pending proposal card offers Simulate impact", await page.locator(simForm).count() === 1);
  await Promise.all([page.waitForURL("**/__ioi/intelligence/simulations/**", { timeout: 15000 }), page.click(simForm)]);
  const pageText = await page.evaluate(() => document.body.innerText);
  ok("simulation report page renders scenarios, hash, and before/after deltas",
    /what-if simulation/i.test(pageText) && /deterministic/i.test(pageText) && /sha256:/i.test(pageText)
    && /memory_projection_replay/i.test(pageText) && /Not replayed/.test(pageText) && /launch_replay/.test(pageText) && /ioi_agent_launch_retired/.test(pageText));
  ok("report page leaks no private or secret bodies", !pageText.includes(privMarker) && !pageText.includes(secretMarker));
  await page.goto(`${SHELL}/__ioi/agent-studio#improvements`, { waitUntil: "networkidle" });
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

  // ── Cleanup ──
  await jd("POST", `/v1/hypervisor/intelligence/improvement-proposals/${affProp.improvement_id}/reject`, { reason: "verifier fixture" });
  const skillId = String(applied.applied_ref || "").replace("skill-entry://", "");
  await jd("PATCH", `/v1/hypervisor/skill-entries/${skillId}`, { status: "archived" });
  if (privEntry.entry_id) await jd("PATCH", `/v1/hypervisor/memory-entries/${privEntry.entry_id}`, { status: "archived" });
  if (secretEntry.entry_id) await jd("PATCH", `/v1/hypervisor/memory-entries/${secretEntry.entry_id}`, { status: "archived" });
  await jd("DELETE", `/v1/hypervisor/governance/approval-requests/${skillGate.id}`);
  await jd("DELETE", `/v1/hypervisor/governance/release-controls/${skillRel.id}`);
  await jd("DELETE", `/v1/hypervisor/principals/${encodeURIComponent(reviewer.principalId)}`, undefined, reviewer.operator);
  // R-240 (2026-09-29): the opencode driver was enabled only for the retired launches; nothing to restore.
  const skillAfter = (await jd("GET", `/v1/hypervisor/skill-entries/${skillId}`)).j?.record || {};
  ok("fixtures cleaned (applied skill archived)", skillAfter.status === "archived", skillAfter.status);
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
