#!/usr/bin/env node
// Outcome learning done-bar.
//
// Proves repeated work becomes skills and automation readiness WITHOUT self-modifying behavior:
// deterministic outcome mining (no LLM judging), durable evidence-bound improvement proposals
// (pending → approved → applied | rejected), zero mutation before approve+apply, receipted
// application through the ordinary object lanes, and no private memory leakage.
// GOV-ATTR-1: the policy-apply gate ApprovalRequest is DECIDED by a real authenticated principal —
// the request body names no reviewer, and the record must report that session's server-derived
// `user://<principal_id>`. Canon: `identity-access-and-metering.md`.
//
// RE-TYPED 2026-09-29 (R-240, GoalRun residue). It seeded its pattern signal with two REAL IOI
// Agent launches and applied a learned launch-policy suggestion to a CLONE of a protected seed
// policy. The launch lane and the launch-policy plane left the Hypervisor with goal pursuit in R-192
// (S5-1) — a goal run is an ioi.ai composition over the thread orchestration primitives (standing
// owner ruling 2026-09-24) — so it crashed on its first launch. The mined-candidate clauses are
// dropped (the miner reads only IOI Agent launch records, which nothing produces any more); the
// proposals bind their evidence to receipted Hypervisor records (memory projections) instead; and
// the launch-policy suggestion is kept as what it now is: reviewed through the same gate, its apply
// refused by name (410 `ioi_agent_launch_policy_retired`).
//
// RE-AIMED 2026-09-29 (R-240, launcher leftovers). The improvement plane now refuses a launch-policy
// suggestion at PROPOSE (410 `ioi_agent_launch_policy_retired`, nothing admitted) rather than admitting
// one whose apply could only be refused, and the miner names its four launch-derived signals retired.
// The gate chain and its GOV-ATTR-1 reviewer attribution ride the automation-readiness proposal, which
// applies through that satisfied gate.
//
// Usage: node apps/hypervisor/scripts/verify-hypervisor-outcome-learning-proposals.mjs  (≈1 min)
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
  const principalId = `usr_vfyout${tag}`;
  const email = `vfyout-${tag}@local`;
  const password = `vfyout-${tag}-reviewer-pass`;
  const created = await jd("POST", "/v1/hypervisor/principals", { email, password, principal_id: principalId }, operator);
  const login = (await jd("POST", "/v1/hypervisor/auth/login", { email, password }, { [ANONYMOUS]: "1" })).j || {};
  const token = login.session_token || "";
  const session = { authorization: `Bearer ${token}` };
  const who = token ? (await jd("GET", "/v1/hypervisor/auth/whoami", undefined, session)).j || {} : {};
  const derived = who.authenticated === true ? String(who.principal?.principal_id || "") : "";
  if (!derived) throw new Error(`reviewer identity fixture NOT admitted (create ${created.status}, whoami ${JSON.stringify(who).slice(0, 200)}) — the gate approval cannot cross the real identity seam`);
  return { principalId: derived, ref: `user://${derived}`, headers: session, operator };
}

async function run() {
  const tag = Date.now().toString(16);
  const privMarker = `olpriv-${tag}`;
  const reviewer = await admitReviewer(tag);
  ok("real principal + login session admitted as the deciding identity", !!reviewer.ref, reviewer.ref);
  const privEntry = (await jd("POST", "/v1/hypervisor/memory-entries", { title: `ol-priv-${tag}`, entry_kind: "fact", body: privMarker, sensitivity: "private" })).j?.record || {};

  // ── Evidence: two receipted Hypervisor records (R-240, 2026-09-29: two REAL IOI Agent launches
  // stood here; that lane is retired) ──
  const pattern = `vfyoutcome${tag} produce the demo`;
  const sessionRef = `session://vfyoutcome-${tag}`;
  const evidence = [];
  for (const harness of ["harness-profile:hp_opencode", "harness-profile:hp_deepseek_tui"]) {
    const p = (await jd("POST", "/v1/hypervisor/memory-projections", { harness_profile_ref: harness, session_ref: sessionRef, goal: `${pattern} status artifact` })).j?.projection || {};
    if (p.projection_ref) evidence.push(p.projection_ref);
  }
  ok("two receipted memory projections recorded as the proposals' evidence", evidence.length === 2 && evidence.every((r) => r.startsWith("memory-projection://")), evidence.join(","));

  // ── Mining: deterministic, derived-only ──
  // R-240 (2026-09-29): "repeated successful goal pattern mined" and "repeated harness preference
  // mined" read candidates the miner derives ONLY from IOI Agent launch records; nothing produces
  // one since the launch lane retired, so those two clauses are dropped rather than faked.
  const mining = (await jd("GET", "/v1/hypervisor/intelligence/outcome-mining")).j || {};
  ok("mining is deterministic-only and derived-only", mining.deterministic_signals_only === true && mining.derived_only === true);
  ok("mining leaks no private memory bodies", !JSON.stringify(mining).includes(privMarker));
  ok("mining names the four launch-derived signals retired rather than counting them as zero, and offers no launch-policy candidate",
    ["repeated_successful_goal_pattern", "repeated_automation_ready_intent", "repeated_harness_model_preference", "repeated_failure_blocker_class"].every((sig) => (mining.retired_signals || []).some((r) => r.signal === sig))
    && (mining.candidates || []).every((c) => c.candidate_kind !== "launch_policy_suggestion"),
    (mining.retired_signals || []).map((r) => `${r.signal}:${r.reason_code}`).join(" "));

  // ── Proposals: creation changes nothing ──
  const mkProp = (payload) => jd("POST", "/v1/hypervisor/intelligence/improvement-proposals", payload);
  const noEvidence = await mkProp({ proposal_kind: "skill_improvement", suggested: { title: "x" }, evidence_refs: [] });
  ok("proposals require evidence refs", noEvidence.status === 422 && noEvidence.j?.error?.code === "improvement_evidence_required");
  const credProp = await mkProp({ proposal_kind: "skill_improvement", evidence_refs: ["x://y"], suggested: { title: "x", body: "sealed_client_secret: z" } });
  ok("proposals refuse credential material", credProp.status === 403);

  const skillProp = (await mkProp({
    proposal_kind: "skill_improvement", signal: "repeated_successful_goal_pattern", evidence_refs: evidence,
    confidence: 0.8, suggested: { title: `Skill: vfyoutcome-${tag}`, description: "produce the demo status artifact" },
  })).j?.proposal || {};
  // R-240 (launcher leftovers): a launch-policy suggestion is refused at propose, by name, and
  // nothing is admitted — it once was admitted pending and refused only at apply.
  const proposalsBefore = ((await jd("GET", "/v1/hypervisor/intelligence/improvement-proposals")).j?.proposals || []).length;
  const policyRefused = await mkProp({
    proposal_kind: "launch_policy_suggestion", signal: "repeated_harness_model_preference",
    target_ref: "ioi-agent-policy://pol_fast_local", evidence_refs: evidence,
    suggested: { description: `learned ${tag}`, harness_preferences: { preferred_harness_refs: ["harness-profile:hp_opencode"], excluded_harness_refs: [], allow_fallback: true } },
  });
  const proposalsAfterRefusal = ((await jd("GET", "/v1/hypervisor/intelligence/improvement-proposals")).j?.proposals || []).length;
  ok("a launch-policy suggestion is refused at propose by name (410 ioi_agent_launch_policy_retired) and nothing is admitted",
    policyRefused.status === 410 && policyRefused.j?.error?.code === "ioi_agent_launch_policy_retired" && !policyRefused.j?.proposal
    && proposalsAfterRefusal === proposalsBefore,
    `${policyRefused.status} ${policyRefused.j?.error?.code} · proposals ${proposalsBefore} → ${proposalsAfterRefusal}`);
  const autoProp = (await mkProp({
    proposal_kind: "automation_readiness", signal: "repeated_successful_goal_pattern", evidence_refs: evidence,
    confidence: 0.8, suggested: { title: `Affinity: vfyoutcome-${tag}`, goal_pattern: pattern },
  })).j?.proposal || {};
  const rejectProp = (await mkProp({
    proposal_kind: "skill_improvement", signal: "repeated_manual_correction",
    evidence_refs: ["memory-entry://mem_evidence"], suggested: { title: `Rejected-${tag}` },
  })).j?.proposal || {};
  ok("proposals created pending with evidence bound",
    [skillProp, autoProp, rejectProp].every((p) => p.state === "pending" && String(p.proposal_ref || "").startsWith("improvement-proposal://")));

  const skillsBefore = (await jd("GET", `/v1/hypervisor/skill-entries?q=vfyoutcome-${tag}`)).j?.skills || [];
  const affBefore = (await jd("GET", `/v1/hypervisor/automation-affinities?q=vfyoutcome-${tag}`)).j?.affinities || [];
  // R-240 (2026-09-29): "seed unchanged" left with the launch-policy seeds.
  ok("no mutation on proposal creation (skills/affinities absent)", skillsBefore.length === 0 && affBefore.length === 0);
  const applyEarly = await jd("POST", `/v1/hypervisor/intelligence/improvement-proposals/${skillProp.improvement_id}/apply`);
  ok("apply before approval fails closed", applyEarly.status === 409 && applyEarly.j?.error?.code === "improvement_not_approved");

  // ── Skill promotion ──
  await jd("POST", `/v1/hypervisor/intelligence/improvement-proposals/${skillProp.improvement_id}/approve`);
  const skillApplied = (await jd("POST", `/v1/hypervisor/intelligence/improvement-proposals/${skillProp.improvement_id}/apply`)).j?.proposal || {};
  const skillRef = String(skillApplied.applied_ref || "");
  const skill = (await jd("GET", `/v1/hypervisor/skill-entries/${skillRef.replace("skill-entry://", "")}`)).j?.record || {};
  ok("approved+applied skill proposal creates an ACCEPTED SkillEntry with evidence",
    skillApplied.state === "applied" && skillRef.startsWith("skill-entry://")
    && skill.quality_state === "accepted" && (skill.source_refs || []).length >= 2
    && String((skillApplied.receipt_refs || [])[0] || "").startsWith("receipt://hypervisor/improvement/"));
  const studioSkills = await fetch(`${SHELL}/__ioi/agent-studio`).then((r) => r.text());
  ok("applied skill visible in Agent Studio Skills", studioSkills.includes(`Skill: vfyoutcome-${tag}`));

  // ── Automation readiness: reviewed through the gate, applied only through the approved path ──
  await jd("POST", `/v1/hypervisor/intelligence/improvement-proposals/${autoProp.improvement_id}/approve`);
  // The gate chain is built explicitly so the reviewer attribution is measured (R-240, launcher
  // leftovers: it rode the launch-policy suggestion, which is no longer admitted).
  await jd("POST", `/v1/hypervisor/intelligence/improvement-proposals/${autoProp.improvement_id}/simulate`, { save: true });
  const polGate = (await jd("POST", "/v1/hypervisor/governance/approval-requests", { subject_ref: autoProp.proposal_ref, request_kind: "improvement_apply", reason: "verifier gate" })).j?.approval_request || {};
  // The approval is DECIDED by the admitted reviewer session; the body names nobody (GOV-ATTR-1).
  await jd("PATCH", `/v1/hypervisor/governance/approval-requests/${polGate.id}`, { transition: "approve" }, reviewer.headers);
  const polGateDecided = (await jd("GET", `/v1/hypervisor/governance/approval-requests/${polGate.id}`)).j?.approval_request || {};
  ok("the gate approval is attributed to the SERVER-DERIVED principal of the deciding session",
    polGateDecided.status === "approved" && polGateDecided.reviewer_ref === reviewer.ref,
    `reviewer ${polGateDecided.reviewer_ref} · expected ${reviewer.ref}`);
  const polRel = (await jd("POST", "/v1/hypervisor/governance/release-controls", { release_target_ref: autoProp.proposal_ref, reason: "verifier gate" })).j?.release_control || {};
  await jd("PATCH", `/v1/hypervisor/governance/release-controls/${polRel.id}`, { transition: "open" });
  const bound = (await jd("PATCH", `/v1/hypervisor/intelligence/improvement-proposals/${autoProp.improvement_id}`, { approval_request_ref: polGate.ref, release_control_ref: polRel.ref })).j?.proposal || {};
  ok("the decided approval and the open release bind to the proposal they target",
    bound.approval_request_ref === polGate.ref && bound.release_control_ref === polRel.ref && bound.gate?.approval_status === "approved" && bound.gate?.release_state === "open",
    `${bound.approval_request_ref} · ${bound.release_control_ref} · ${bound.gate?.posture}`);
  const autoApplied = (await jd("POST", `/v1/hypervisor/intelligence/improvement-proposals/${autoProp.improvement_id}/apply`)).j?.proposal || {};
  const affRef = String(autoApplied.applied_ref || "");
  const affinity = (await jd("GET", `/v1/hypervisor/automation-affinities/${affRef.replace("automation-affinity://", "")}`)).j?.record || {};
  ok("automation-readiness suggestion creates the affinity only on apply",
    affRef.startsWith("automation-affinity://") && affinity.goal_pattern === pattern);

  // ── Rejection preserves evidence ──
  const rejected = (await jd("POST", `/v1/hypervisor/intelligence/improvement-proposals/${rejectProp.improvement_id}/reject`, { reason: "not useful" })).j?.proposal || {};
  ok("rejected proposal preserves its evidence", rejected.state === "rejected" && (rejected.evidence_refs || []).length === 1);

  // ── Ledger + leakage ──
  const ledger = await jd("GET", "/v1/hypervisor/work-ledger");
  const appliedEntries = (ledger.j?.entries || []).filter((e) => e.kind === "improvement_applied");
  ok("Work Ledger indexes the improvement-applied receipts — the skill and the affinity",
    appliedEntries.filter((e) => [skillApplied, autoApplied].some((p) => e.proposal_ref === p.proposal_ref)).length === 2);
  const allProps = await jd("GET", "/v1/hypervisor/intelligence/improvement-proposals");
  ok("no private memory body leaks into proposals, mining, or the improvement UI",
    !JSON.stringify(allProps.j).includes(privMarker)
    && !JSON.stringify(mining).includes(privMarker)
    && !(studioSkills.split('id="improvement-proposals"')[1] || "").split("<h2")[0].includes(privMarker));

  // ── UI panel ──
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1600, height: 1000 } });
  await STACK.signIn(page);
  const consoleErrors = [];
  page.on("pageerror", (e) => consoleErrors.push(String(e)));
  await page.goto(`${SHELL}/__ioi/agent-studio#improvements`, { waitUntil: "networkidle" });
  await page.waitForSelector("#improvement-proposals", { timeout: 15000 });
  const panel = await page.locator("#improvement-proposals").evaluate((el) => {
    let text = el.textContent || "";
    let node = el.nextElementSibling;
    while (node && node.tagName !== "H2") { text += node.textContent || ""; node = node.nextElementSibling; }
    return text;
  });
  ok("Improvement proposals panel shows states, signals, evidence, and mined candidates — and names the signals it no longer mines",
    /applied/.test(panel) && /repeated_successful_goal_pattern/.test(panel) && /Mined candidates/.test(panel)
    && /Not mined:/.test(panel) && /repeated_harness_model_preference/.test(panel));
  ok("no console errors", consoleErrors.length === 0, consoleErrors.slice(0, 2).join(" | "));
  await browser.close();
  const ft = await fetch(`${SHELL}/__ioi/fallthrough`).then((r) => r.json()).catch(() => ({}));
  ok("fallthrough stays empty", Array.isArray(ft.proxied) && ft.proxied.length === 0);

  // ── Cleanup ──
  await jd("PATCH", `/v1/hypervisor/skill-entries/${skillRef.replace("skill-entry://", "")}`, { status: "archived" });
  await jd("PATCH", `/v1/hypervisor/automation-affinities/${affRef.replace("automation-affinity://", "")}`, { status: "archived" });
  if (privEntry.entry_id) await jd("PATCH", `/v1/hypervisor/memory-entries/${privEntry.entry_id}`, { status: "archived" });
  await jd("DELETE", `/v1/hypervisor/governance/approval-requests/${polGate.id}`);
  await jd("DELETE", `/v1/hypervisor/governance/release-controls/${polRel.id}`);
  await jd("DELETE", `/v1/hypervisor/principals/${encodeURIComponent(reviewer.principalId)}`, undefined, reviewer.operator);
  // R-240 (2026-09-29): the opencode driver was enabled only to run the retired launches, so there
  // is no driver posture to restore; the fixtures this run applied are what it archives.
  const skillAfter = (await jd("GET", `/v1/hypervisor/skill-entries/${skillRef.replace("skill-entry://", "")}`)).j?.record || {};
  const affAfter = (await jd("GET", `/v1/hypervisor/automation-affinities/${affRef.replace("automation-affinity://", "")}`)).j?.record || {};
  ok("fixtures cleaned (applied skill and affinity archived)", skillAfter.status === "archived" && affAfter.status === "archived", `${skillAfter.status}/${affAfter.status}`);
}

run().then(() => {
  let fail = 0;
  for (const r of results) { console.log(`  ${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? `  (${r.detail})` : ""}`); if (!r.pass) fail++; }
  console.log(`\n${results.length - fail}/${results.length} passed`);
  console.log(`outcome learning readiness: ${fail ? "FAIL" : "OK"}`);
  process.exit(fail ? 1 : 0);
}).catch((e) => {
  console.error("verifier crashed:", e);
  process.exit(1);
});
