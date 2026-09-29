#!/usr/bin/env node
// Improvement governance gates done-bar.
//
// Proves high-impact learned improvements CANNOT apply without a FRESH simulation, an
// APPROVED ApprovalRequest, and an OPEN ReleaseControl targeting the proposal or its
// simulation report — enforced LIVE at apply time with deterministic reason codes
// (simulation_required, simulation_stale, approval_required, approval_not_approved,
// release_control_required, release_control_not_open) — while low-impact proposals keep
// their existing behavior, receipts + Work Ledger cite the full governance chain, and the
// Agent Studio panel walks the whole gate (posture chip, disabled Apply, one-click
// request/approve/release).
// GOV-ATTR-1: the gate ApprovalRequest is DECIDED by a real authenticated principal — the request
// body names no reviewer, and the record must report that session's server-derived
// `user://<principal_id>`. Canon: `identity-access-and-metering.md`.
//
// RE-TYPED 2026-09-29 (R-240, GoalRun residue). Its high-impact fixture was a learned launch-policy
// patch whose what-if introduced blockers into two REAL IOI Agent launches' strategy selection, and
// its apply landed an `ioi-agent-policy://` variant. R-192 (S5-1) took goal pursuit out of the
// Hypervisor — a goal run is an ioi.ai composition over the thread orchestration primitives
// (standing owner ruling 2026-09-24) — so the launch lane and the policy plane are gone and the
// verifier crashed on its first launch. The gate is unchanged, so the walk now rides a SKILL
// improvement made deterministically high-impact by three receipted memory projections it changes
// (the platform's own replay subjects); `simulation_required` is still measured on an unsimulated
// launch-policy suggestion, the one kind the gate always holds for a simulation.
//
// Usage: node apps/hypervisor/scripts/verify-hypervisor-improvement-governance-gates.mjs  (≈1–2 min)
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
  const principalId = `usr_vfygov${tag}`;
  const email = `vfygov-${tag}@local`;
  const password = `vfygov-${tag}-reviewer-pass`;
  const created = await jd("POST", "/v1/hypervisor/principals", { email, password, principal_id: principalId }, operator);
  const login = (await jd("POST", "/v1/hypervisor/auth/login", { email, password }, { [ANONYMOUS]: "1" })).j || {};
  const token = login.session_token || "";
  const session = { authorization: `Bearer ${token}` };
  const who = token ? (await jd("GET", "/v1/hypervisor/auth/whoami", undefined, session)).j || {} : {};
  const derived = who.authenticated === true ? String(who.principal?.principal_id || "") : "";
  if (!derived) throw new Error(`reviewer identity fixture NOT admitted (create ${created.status}, whoami ${JSON.stringify(who).slice(0, 200)}) — the gate approval cannot cross the real identity seam`);
  return { principalId: derived, ref: `user://${derived}`, headers: session, operator };
}
const apply = (id) => jd("POST", `/v1/hypervisor/intelligence/improvement-proposals/${id}/apply`);
const getProp = async (id) => (await jd("GET", `/v1/hypervisor/intelligence/improvement-proposals/${id}`)).j?.proposal || {};

// A skill every replayed projection would carry: deterministically high impact once three
// projections change (the simulation's own `changed >= 3` rule).
const highImpactSuggested = (tag, which) => ({
  title: `Gated skill ${which} vfygov-${tag}`,
  description: "deterministically high-impact fixture: every replayed projection would include it",
});

async function run() {
  const tag = Date.now().toString(16);
  const reviewer = await admitReviewer(tag);
  ok("real principal + login session admitted as the deciding identity", !!reviewer.ref, reviewer.ref);
  // R-240 (2026-09-29): two REAL IOI Agent launches stood here as replay subjects; that lane is retired.
  const subjects = [];
  for (const harness of ["harness-profile:hp_opencode", "harness-profile:hp_deepseek_tui", "harness-profile:hp_codex"]) {
    const p = (await jd("POST", "/v1/hypervisor/memory-projections", { harness_profile_ref: harness, session_ref: `session://vfygov-${tag}`, goal: `vfygov${tag} exercise the governance gate` })).j?.projection || {};
    if (p.projection_ref) subjects.push(p.projection_ref);
  }
  ok("three receipted memory projections recorded as replay subjects", subjects.length === 3, subjects.join(","));

  const mkProp = (payload) => jd("POST", "/v1/hypervisor/intelligence/improvement-proposals", payload);

  // ── simulation_required: policy improvements cannot apply unsimulated ──
  const propP = (await mkProp({
    proposal_kind: "launch_policy_suggestion", signal: "repeated_harness_model_preference",
    evidence_refs: subjects, suggested: { description: `vfygov-${tag} unsimulated policy suggestion` },
  })).j?.proposal || {};
  ok("unsimulated policy proposal postures simulation_required",
    propP.gate?.posture === "simulation_required" || (await getProp(propP.improvement_id)).gate?.posture === "simulation_required");
  await jd("POST", `/v1/hypervisor/intelligence/improvement-proposals/${propP.improvement_id}/approve`);
  const noSim = await apply(propP.improvement_id);
  ok("apply without simulation blocks: simulation_required", noSim.status === 409 && noSim.j?.error?.code === "simulation_required");

  // ── High-impact simulation names an ENFORCED gate with its satisfiable targets ──
  const SUGGESTED_A = highImpactSuggested(tag, "A");
  const propA = (await mkProp({
    proposal_kind: "skill_improvement", signal: "repeated_successful_goal_pattern",
    evidence_refs: subjects, suggested: SUGGESTED_A,
  })).j?.proposal || {};
  await jd("POST", `/v1/hypervisor/intelligence/improvement-proposals/${propA.improvement_id}/approve`);
  const sim = (await jd("POST", `/v1/hypervisor/intelligence/improvement-proposals/${propA.improvement_id}/simulate`, { save: true })).j?.report || {};
  const simRef = String(sim.simulation_ref || "");
  ok("saved simulation is high-impact with an enforced requirement + gate targets",
    sim.governance?.high_impact === true && sim.governance?.enforced === true
    && String(sim.governance?.requirement || "").startsWith("enforced:")
    && JSON.stringify(sim.governance?.satisfiable_target_refs) === JSON.stringify([propA.proposal_ref, simRef]),
    JSON.stringify(sim.summary));

  // ── approval_required → binding validation → approval_not_approved ──
  const noAppr = await apply(propA.improvement_id);
  ok("apply with high-impact simulation but no controls blocks: approval_required",
    noAppr.status === 409 && noAppr.j?.error?.code === "approval_required"
    && (await getProp(propA.improvement_id)).gate?.posture === "awaiting_approval");
  const badRef = await jd("PATCH", `/v1/hypervisor/intelligence/improvement-proposals/${propA.improvement_id}`, { approval_request_ref: "approval-request://appr_nonexistent" });
  const foreign = (await jd("POST", "/v1/hypervisor/governance/approval-requests", { subject_ref: simRef ? "improvement-proposal://imp_nonexistent" : "", request_kind: "improvement_apply", reason: `vfygov-${tag}-foreign` })).j?.approval_request;
  ok("binding validates live: unresolved refs rejected", badRef.status === 422 && badRef.j?.error?.code === "governance_ref_unresolved", JSON.stringify(badRef.j?.error || {}));
  const apprA = (await jd("POST", "/v1/hypervisor/governance/approval-requests", { subject_ref: propA.proposal_ref, request_kind: "improvement_apply", reason: `vfygov-${tag}` })).j?.approval_request || {};
  const bindPending = await jd("PATCH", `/v1/hypervisor/intelligence/improvement-proposals/${propA.improvement_id}`, { approval_request_ref: apprA.ref });
  const pendingBlocked = await apply(propA.improvement_id);
  ok("pending ApprovalRequest blocks: approval_not_approved",
    bindPending.status === 200 && pendingBlocked.status === 409 && pendingBlocked.j?.error?.code === "approval_not_approved");

  // ── release_control_required → release_control_not_open (release may target the SIM report) ──
  // The approval is DECIDED by the admitted reviewer session; the body names nobody (GOV-ATTR-1).
  await jd("PATCH", `/v1/hypervisor/governance/approval-requests/${apprA.id}`, { transition: "approve" }, reviewer.headers);
  const apprADecided = (await jd("GET", `/v1/hypervisor/governance/approval-requests/${apprA.id}`)).j?.approval_request || {};
  ok("the gate approval is attributed to the SERVER-DERIVED principal of the deciding session",
    apprADecided.status === "approved" && apprADecided.reviewer_ref === reviewer.ref,
    `reviewer ${apprADecided.reviewer_ref} · expected ${reviewer.ref}`);
  const noRel = await apply(propA.improvement_id);
  ok("approved approval alone blocks: release_control_required", noRel.status === 409 && noRel.j?.error?.code === "release_control_required");
  const relA = (await jd("POST", "/v1/hypervisor/governance/release-controls", { release_target_ref: simRef, reason: `vfygov-${tag}` })).j?.release_control || {};
  await jd("PATCH", `/v1/hypervisor/intelligence/improvement-proposals/${propA.improvement_id}`, { release_control_ref: relA.ref });
  const closedBlocked = await apply(propA.improvement_id);
  ok("closed ReleaseControl blocks: release_control_not_open", closedBlocked.status === 409 && closedBlocked.j?.error?.code === "release_control_not_open");
  await jd("PATCH", `/v1/hypervisor/governance/release-controls/${relA.id}`, { transition: "open" });
  ok("approved + open controls posture READY", (await getProp(propA.improvement_id)).gate?.posture === "ready");

  // ── Freshness: mutating the proposal makes the simulation stale even with controls satisfied ──
  await jd("PATCH", `/v1/hypervisor/intelligence/improvement-proposals/${propA.improvement_id}`, { suggested: { ...SUGGESTED_A, description: "changed after the simulation" } });
  const staleBlocked = await apply(propA.improvement_id);
  ok("post-simulation mutation blocks: simulation_stale (controls alone cannot pass a stale preview)",
    staleBlocked.status === 409 && staleBlocked.j?.error?.code === "simulation_stale"
    && (await getProp(propA.improvement_id)).gate?.posture === "simulation_stale");
  await jd("PATCH", `/v1/hypervisor/intelligence/improvement-proposals/${propA.improvement_id}`, { suggested: SUGGESTED_A });
  ok("freshness is content identity: restoring the simulated payload restores READY (no re-simulation needed)",
    (await getProp(propA.improvement_id)).gate?.posture === "ready");

  // ── Gate satisfied → apply lands, citing the full governance chain ──
  const appliedA = (await apply(propA.improvement_id)).j?.proposal || {};
  ok("fresh simulation + approved approval + open release allow apply",
    appliedA.state === "applied" && String(appliedA.applied_ref || "").startsWith("skill-entry://"));
  const ledger = (await jd("GET", "/v1/hypervisor/work-ledger")).j?.entries || [];
  const entry = ledger.find((e) => e.kind === "improvement_applied" && e.proposal_ref === propA.proposal_ref);
  ok("receipt + Work Ledger cite simulation, approval, and release refs",
    !!entry && entry.simulation_ref === simRef && entry.approval_request_ref === apprA.ref
    && entry.release_control_ref === relA.ref && entry.report_hash === sim.report_hash);

  // ── Low-impact + no-simulation paths keep existing behavior ──
  const propLow = (await mkProp({
    proposal_kind: "automation_readiness", signal: "repeated_successful_goal_pattern",
    evidence_refs: subjects, suggested: { title: `Affinity vfygov-${tag}`, goal_pattern: `zzz-nomatch-${tag}` },
  })).j?.proposal || {};
  const lowSim = (await jd("POST", `/v1/hypervisor/intelligence/improvement-proposals/${propLow.improvement_id}/simulate`, { save: true })).j?.report || {};
  await jd("POST", `/v1/hypervisor/intelligence/improvement-proposals/${propLow.improvement_id}/approve`);
  const appliedLow = (await apply(propLow.improvement_id)).j?.proposal || {};
  ok("low-impact simulated proposal applies WITHOUT governance controls",
    lowSim.governance?.high_impact === false && appliedLow.state === "applied");
  const propSkill = (await mkProp({
    proposal_kind: "skill_improvement", signal: "repeated_successful_goal_pattern",
    evidence_refs: subjects, suggested: { title: `Skill vfygov-${tag}`, description: "ungated low-impact lane" },
  })).j?.proposal || {};
  await jd("POST", `/v1/hypervisor/intelligence/improvement-proposals/${propSkill.improvement_id}/approve`);
  const appliedSkill = (await apply(propSkill.improvement_id)).j?.proposal || {};
  ok("unsimulated non-policy proposal keeps existing behavior (no_simulation, applies)",
    appliedSkill.state === "applied" && String(appliedSkill.applied_ref || "").startsWith("skill-entry://"));

  // ── UI: full gate walk on a second high-impact proposal ──
  const propB = (await mkProp({
    proposal_kind: "skill_improvement", signal: "repeated_successful_goal_pattern",
    evidence_refs: subjects, suggested: highImpactSuggested(tag, "B"),
  })).j?.proposal || {};
  await jd("POST", `/v1/hypervisor/intelligence/improvement-proposals/${propB.improvement_id}/simulate`, { save: true });
  await jd("POST", `/v1/hypervisor/intelligence/improvement-proposals/${propB.improvement_id}/approve`);
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1600, height: 1000 } });
  await STACK.signIn(page);
  const consoleErrors = [];
  page.on("pageerror", (e) => consoleErrors.push(String(e)));
  const studio = `${SHELL}/__ioi/agent-studio#launch-policies`;
  await page.goto(studio, { waitUntil: "networkidle" });
  await page.waitForSelector("#improvement-proposals", { timeout: 15000 });
  const bid = propB.improvement_id;
  ok("card shows awaiting-approval posture with a visibly blocked Apply",
    await page.locator(`button[title="apply blocked: approval_required"][disabled]`).count() >= 1
    && (await page.locator(`[data-gov="${bid}"]`).innerText()).match(/request approval/i) !== null);
  await Promise.all([page.waitForURL("**/agent-studio**"), page.click(`form[action="/__ioi/agent-studio/improvements/${bid}/governance/request-approval"] button`)]);
  await page.goto(studio, { waitUntil: "networkidle" });
  await Promise.all([page.waitForURL("**/agent-studio**"), page.click(`[data-gov="${bid}"] form[action*="/governance/approvals/"] button`)]);
  await page.goto(studio, { waitUntil: "networkidle" });
  await Promise.all([page.waitForURL("**/agent-studio**"), page.click(`form[action="/__ioi/agent-studio/improvements/${bid}/governance/open-release"] button`)]);
  await page.goto(studio, { waitUntil: "networkidle" });
  await Promise.all([page.waitForURL("**/agent-studio**"), page.click(`[data-gov="${bid}"] form[action*="/governance/releases/"] button`)]);
  await page.goto(studio, { waitUntil: "networkidle" });
  const bAfter = await getProp(bid);
  ok("one-click UI walk satisfies the whole gate (request → approve → release → open = ready)",
    bAfter.gate?.posture === "ready" && (await page.locator(`[data-gov="${bid}"]`).innerText()).match(/approved/i) !== null
    && await page.locator(`form[action="/__ioi/agent-studio/improvements/${bid}/apply"] button`).count() === 1);
  await Promise.all([page.waitForURL("**/agent-studio**"), page.click(`form[action="/__ioi/agent-studio/improvements/${bid}/apply"] button`)]);
  const bApplied = await getProp(bid);
  ok("UI apply lands once the gate passes", bApplied.state === "applied");

  // ── Report page names its satisfiable governance targets; ledger drawer backlinks the chain ──
  const simId = String(bApplied.latest_simulation_ref || "").replace("simulation-report://", "");
  await page.goto(`${SHELL}/__ioi/intelligence/simulations/${simId}`, { waitUntil: "networkidle" });
  const repText = await page.evaluate(() => document.body.innerText);
  ok("simulation report page shows enforced gate + exact satisfiable target refs",
    /gate enforced at apply/i.test(repText) && repText.includes(bApplied.proposal_ref) && repText.includes(bApplied.latest_simulation_ref));
  await page.goto(`${SHELL}/__ioi/work-ledger`, { waitUntil: "networkidle" });
  await page.locator(".wlrow", { hasText: "improvement_applied" }).first().click();
  const drawer = await page.locator("#wl-drawer").innerText();
  ok("Work Ledger drawer backlinks simulation + approval + release",
    drawer.includes("simulation-report://") && drawer.includes("approval-request://") && drawer.includes("release-control://"));
  ok("no console errors", consoleErrors.length === 0, consoleErrors.slice(0, 2).join(" | "));
  await browser.close();
  const ft = await fetch(`${SHELL}/__ioi/fallthrough`).then((r) => r.json()).catch(() => ({}));
  ok("fallthrough stays empty", Array.isArray(ft.proxied) && ft.proxied.length === 0);

  // ── Cleanup ──
  const skillIds = [appliedA, bApplied, appliedSkill].map((p) => String(p.applied_ref || "").replace("skill-entry://", "")).filter(Boolean);
  for (const id of skillIds) await jd("PATCH", `/v1/hypervisor/skill-entries/${id}`, { status: "archived" });
  const affId = String(appliedLow.applied_ref || "").replace("automation-affinity://", "");
  await jd("PATCH", `/v1/hypervisor/automation-affinities/${affId}`, { status: "archived" });
  await jd("POST", `/v1/hypervisor/intelligence/improvement-proposals/${propP.improvement_id}/reject`, { reason: "verifier fixture" });
  const controls = [
    ["approval-requests", apprA.id],
    ["approval-requests", foreign?.id],
    ["approval-requests", String(bApplied.approval_request_ref || "").replace("approval-request://", "")],
    ["release-controls", relA.id],
    ["release-controls", String(bApplied.release_control_ref || "").replace("release-control://", "")],
  ];
  for (const [family, id] of controls) {
    if (id) await jd("DELETE", `/v1/hypervisor/governance/${family}/${id}`);
  }
  await jd("DELETE", `/v1/hypervisor/principals/${encodeURIComponent(reviewer.principalId)}`, undefined, reviewer.operator);
  // R-240 (2026-09-29): the opencode driver was enabled only for the retired launches; what this run
  // applied is what it archives.
  const archived = [];
  for (const id of skillIds) archived.push(((await jd("GET", `/v1/hypervisor/skill-entries/${id}`)).j?.record || {}).status);
  archived.push(((await jd("GET", `/v1/hypervisor/automation-affinities/${affId}`)).j?.record || {}).status);
  ok("fixtures cleaned (applied skills and affinity archived)", archived.length === 4 && archived.every((s) => s === "archived"), archived.join(","));
}

run().then(() => {
  let fail = 0;
  for (const r of results) { console.log(`  ${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? `  (${r.detail})` : ""}`); if (!r.pass) fail++; }
  console.log(`\n${results.length - fail}/${results.length} passed`);
  console.log(`improvement governance gates readiness: ${fail ? "FAIL" : "OK"}`);
  process.exit(fail ? 1 : 0);
}).catch((e) => {
  console.error("verifier crashed:", e);
  process.exit(1);
});
