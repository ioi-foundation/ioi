#!/usr/bin/env node
// Outcome learning done-bar.
//
// Proves IOI Agent turns repeated work into skills, policy suggestions, and automation
// readiness WITHOUT self-modifying behavior: deterministic outcome mining (no LLM judging),
// durable evidence-bound improvement proposals (pending → approved → applied | rejected),
// zero mutation before approve+apply, receipted application through the ordinary object
// lanes, protected seed policies immutable (clone-only), and no private memory leakage.
//
// Runs two REAL direct launches with an identical goal to seed the pattern signal (≈30s).
// Usage: node apps/hypervisor/scripts/verify-hypervisor-outcome-learning-proposals.mjs

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
const launch = async (goal) => {
  const a = await jd("POST", "/v1/hypervisor/ioi-agent/launch", { goal, strategy: "direct" });
  const grant = mintApprovalGrant({ policyHash: a.j.approval.policy_hash, requestHash: a.j.approval.request_hash });
  return jd("POST", "/v1/hypervisor/ioi-agent/launch", { launch_id: a.j.launch_id, wallet_approval_grant: grant });
};

async function run() {
  const tag = Date.now().toString(16);
  const privMarker = `olpriv-${tag}`;
  await jd("POST", "/v1/hypervisor/harness-profiles/hp_opencode/enable");
  const privEntry = (await jd("POST", "/v1/hypervisor/memory-entries", { title: `ol-priv-${tag}`, entry_kind: "fact", body: privMarker, sensitivity: "private" })).j?.record || {};

  // ── Seed repeated identical successful work (REAL launches) ──
  const goal = `vfyoutcome${tag} produce the demo status artifact`;
  const l1 = await launch(`${goal} first`);
  const l2 = await launch(`${goal} second`);
  ok("two real launches with a shared goal pattern executed", l1.status === 200 && l2.status === 200);

  // ── Mining: deterministic candidates ──
  const mining = (await jd("GET", "/v1/hypervisor/intelligence/outcome-mining")).j || {};
  const pattern = `vfyoutcome${tag} produce the demo`;
  const skillCand = (mining.candidates || []).find((c) => c.candidate_kind === "skill_improvement" && c.pattern === pattern);
  const autoCand = (mining.candidates || []).find((c) => c.candidate_kind === "automation_readiness" && c.pattern === pattern);
  const harnessCand = (mining.candidates || []).find((c) => c.signal === "repeated_harness_model_preference");
  ok("mining is deterministic-only and derived-only", mining.deterministic_signals_only === true && mining.derived_only === true);
  ok("repeated successful goal pattern mined (skill + automation candidates, evidence-bound)",
    !!skillCand && !!autoCand && skillCand.occurrences >= 2 && (skillCand.evidence_refs || []).length >= 2, skillCand?.pattern);
  ok("repeated harness preference mined", !!harnessCand && (harnessCand.evidence_refs || []).length >= 3);
  ok("mining leaks no private memory bodies", !JSON.stringify(mining).includes(privMarker));

  // ── Proposals: creation changes nothing ──
  const mkProp = (payload) => jd("POST", "/v1/hypervisor/intelligence/improvement-proposals", payload);
  const noEvidence = await mkProp({ proposal_kind: "skill_improvement", suggested: { title: "x" }, evidence_refs: [] });
  ok("proposals require evidence refs", noEvidence.status === 422 && noEvidence.j?.error?.code === "improvement_evidence_required");
  const credProp = await mkProp({ proposal_kind: "skill_improvement", evidence_refs: ["x://y"], suggested: { title: "x", body: "sealed_client_secret: z" } });
  ok("proposals refuse credential material", credProp.status === 403);

  const skillProp = (await mkProp({
    proposal_kind: "skill_improvement", signal: skillCand.signal, evidence_refs: skillCand.evidence_refs,
    confidence: skillCand.confidence, suggested: { ...skillCand.suggested, title: `Skill: vfyoutcome-${tag}` },
  })).j?.proposal || {};
  const policyProp = (await mkProp({
    proposal_kind: "launch_policy_suggestion", signal: "repeated_harness_model_preference",
    target_ref: "ioi-agent-policy://pol_fast_local", evidence_refs: harnessCand.evidence_refs,
    suggested: { description: `learned ${tag}`, harness_preferences: { preferred_harness_refs: ["harness-profile:hp_opencode"], excluded_harness_refs: [], allow_fallback: true } },
  })).j?.proposal || {};
  const autoProp = (await mkProp({
    proposal_kind: "automation_readiness", signal: autoCand.signal, evidence_refs: autoCand.evidence_refs,
    confidence: autoCand.confidence, suggested: { title: `Affinity: vfyoutcome-${tag}`, goal_pattern: pattern },
  })).j?.proposal || {};
  const rejectProp = (await mkProp({
    proposal_kind: "skill_improvement", signal: "repeated_manual_correction",
    evidence_refs: ["memory-entry://mem_evidence"], suggested: { title: `Rejected-${tag}` },
  })).j?.proposal || {};
  ok("proposals created pending with evidence bound",
    [skillProp, policyProp, autoProp, rejectProp].every((p) => p.state === "pending" && String(p.proposal_ref || "").startsWith("improvement-proposal://")));

  const skillsBefore = (await jd("GET", `/v1/hypervisor/skill-entries?q=vfyoutcome-${tag}`)).j?.skills || [];
  const affBefore = (await jd("GET", `/v1/hypervisor/automation-affinities?q=vfyoutcome-${tag}`)).j?.affinities || [];
  const seedBefore = (await jd("GET", "/v1/hypervisor/ioi-agent/launch-policies/pol_fast_local")).j?.policy || {};
  ok("no mutation on proposal creation (skills/affinities absent, seed unchanged)",
    skillsBefore.length === 0 && affBefore.length === 0 && seedBefore.protected === true && !String(seedBefore.description || "").includes(`learned ${tag}`));
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

  // ── Launch-policy suggestion: protected seed applies via clone only ──
  await jd("POST", `/v1/hypervisor/intelligence/improvement-proposals/${policyProp.improvement_id}/approve`);
  // Governance gates (enforced since the simulation cut): policy improvements need a fresh
  // saved simulation; if it lands high-impact, an approved ApprovalRequest + open ReleaseControl.
  await jd("POST", `/v1/hypervisor/intelligence/improvement-proposals/${policyProp.improvement_id}/simulate`, { save: true });
  const polGate = (await jd("POST", "/v1/hypervisor/governance/approval-requests", { subject_ref: policyProp.proposal_ref, request_kind: "improvement_apply", reason: "verifier gate" })).j?.approval_request || {};
  await jd("PATCH", `/v1/hypervisor/governance/approval-requests/${polGate.id}`, { transition: "approve", reviewer_ref: "principal://verifier" });
  const polRel = (await jd("POST", "/v1/hypervisor/governance/release-controls", { release_target_ref: policyProp.proposal_ref, reason: "verifier gate" })).j?.release_control || {};
  await jd("PATCH", `/v1/hypervisor/governance/release-controls/${polRel.id}`, { transition: "open" });
  await jd("PATCH", `/v1/hypervisor/intelligence/improvement-proposals/${policyProp.improvement_id}`, { approval_request_ref: polGate.ref, release_control_ref: polRel.ref });
  const policyApplied = (await jd("POST", `/v1/hypervisor/intelligence/improvement-proposals/${policyProp.improvement_id}/apply`)).j?.proposal || {};
  const cloneId = String(policyApplied.applied_ref || "").replace("ioi-agent-policy://", "");
  const clone = (await jd("GET", `/v1/hypervisor/ioi-agent/launch-policies/${cloneId}`)).j?.policy || {};
  const seedAfter = (await jd("GET", "/v1/hypervisor/ioi-agent/launch-policies/pol_fast_local")).j?.policy || {};
  ok("policy suggestion applied to a CLONE; protected seed untouched",
    clone.protected === false && clone.cloned_from === "ioi-agent-policy://pol_fast_local"
    && String(clone.description || "").includes(`learned ${tag}`)
    && seedAfter.protected === true && !String(seedAfter.description || "").includes(`learned ${tag}`));
  const directPatch = await jd("PATCH", "/v1/hypervisor/ioi-agent/launch-policies/pol_fast_local", { description: "hack" });
  ok("direct mutation of protected seeds still fails closed", directPatch.status === 409);

  // ── Automation readiness: applies only through the approved path ──
  await jd("POST", `/v1/hypervisor/intelligence/improvement-proposals/${autoProp.improvement_id}/approve`);
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
  ok("Work Ledger indexes improvement-applied receipts",
    (ledger.j?.entries || []).filter((e) => e.kind === "improvement_applied" && [skillApplied, policyApplied, autoApplied].some((p) => e.proposal_ref === p.proposal_ref)).length === 3);
  const allProps = await jd("GET", "/v1/hypervisor/intelligence/improvement-proposals");
  ok("no private memory body leaks into proposals, mining, or the improvement UI",
    !JSON.stringify(allProps.j).includes(privMarker)
    && !JSON.stringify(mining).includes(privMarker)
    && !(studioSkills.split('id="improvement-proposals"')[1] || "").split("<h2")[0].includes(privMarker));

  // ── UI panel ──
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1600, height: 1000 } });
  const consoleErrors = [];
  page.on("pageerror", (e) => consoleErrors.push(String(e)));
  await page.goto(`${SHELL}/__ioi/agent-studio#launch-policies`, { waitUntil: "networkidle" });
  await page.waitForSelector("#improvement-proposals", { timeout: 15000 });
  const panel = await page.locator("#improvement-proposals").evaluate((el) => {
    let text = el.textContent || "";
    let node = el.nextElementSibling;
    while (node && node.tagName !== "H2") { text += node.textContent || ""; node = node.nextElementSibling; }
    return text;
  });
  ok("Improvement proposals panel shows states, signals, evidence, and mined candidates",
    /applied/.test(panel) && /repeated_successful_goal_pattern|repeated_harness_model_preference/.test(panel) && /Mined candidates/.test(panel));
  ok("no console errors", consoleErrors.length === 0, consoleErrors.slice(0, 2).join(" | "));
  await browser.close();
  const ft = await fetch(`${SHELL}/__ioi/fallthrough`).then((r) => r.json()).catch(() => ({}));
  ok("fallthrough stays empty", Array.isArray(ft.proxied) && ft.proxied.length === 0);

  // ── Cleanup + posture restore ──
  await jd("PATCH", `/v1/hypervisor/skill-entries/${skillRef.replace("skill-entry://", "")}`, { status: "archived" });
  await jd("PATCH", `/v1/hypervisor/automation-affinities/${affRef.replace("automation-affinity://", "")}`, { status: "archived" });
  await jd("DELETE", `/v1/hypervisor/ioi-agent/launch-policies/${cloneId}`);
  await jd("PATCH", `/v1/hypervisor/memory-entries/${privEntry.entry_id}`, { status: "archived" });
  await jd("DELETE", `/v1/hypervisor/governance/approval-requests/${polGate.id}`);
  await jd("DELETE", `/v1/hypervisor/governance/release-controls/${polRel.id}`);
  await jd("POST", "/v1/hypervisor/harness-profiles/hp_opencode/disable");
  const fin = await jd("GET", "/v1/hypervisor/harness-profiles");
  ok("fixtures cleaned + drivers restored",
    (fin.j?.profiles || []).filter((p) => p.harness === "opencode").every((p) => p.lifecycle.status === "disabled"));
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
